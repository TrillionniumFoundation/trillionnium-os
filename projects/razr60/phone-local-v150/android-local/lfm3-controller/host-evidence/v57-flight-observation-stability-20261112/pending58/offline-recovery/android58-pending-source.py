#!/usr/bin/env python3
"""Build a sealed main58 source successor on Pocket4 and reuse signed54 native payloads exactly.
No native compiler, signer, publication, download, ADB or phone action is executed.
"""
import gzip, hashlib, io, json, os, re, signal, stat, struct, subprocess, sys, tarfile, time, traceback, zipfile
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

CONFIG = json.loads("{\"schema\":\"hepta.main58-pocket4-java-native-reuse-config.v1\",\"root\":\"/home/alex/hepta-local-007f-20261111/v58-main-p4-android-r1\",\"base_root\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4\",\"aggregate\":{\"git\":\"94ca147166c4e4c7faa5bd32085c5431eb36f4b1\",\"bytes\":1465984,\"sha256\":\"600ff7c4198fc83d4e93399fc6bf039800805f4458406b4182952ddcff89b95b\"},\"decoded_input\":{\"bytes\":1605061,\"sha256\":\"120cc1714b837e19d56acc4138bcb2194124b1100293f6bf2a8f71c32fb0ed33\"},\"source_file_count\":595,\"overlay_file_count\":40,\"compiler_input_count\":217,\"java_source_count\":115,\"source_inventory_sha256\":\"b44d3a9d9083a86d5fff36dfcc0c27958ef047a05df928923ef7c2e204cb23d6\",\"base_source_commit\":\"42d3a0f447807659c0f78c8273edee01dd1b734f\",\"base_source_inventory_sha256\":\"8675c0c438cdf10f599c23a3a6305a5678fd59270f09b4f73a43f7a67bf2237d\",\"base_signed_result\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/assembly-r1/RESULT.json\",\"bytes\":15659,\"sha256\":\"eadc9dbb63b411015571a488377be6a8704c9f78415169a5164c8f13571f0f72\"},\"base_apk\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/out/hepta-local-0.54.0.apk\",\"bytes\":20985685,\"sha256\":\"0729f54704a058049e12041c7f901b1b6650924500663cf9952a03d6a33a8b8a\"},\"base_archive\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/mac-artifacts.tar.gz\",\"bytes\":562137,\"sha256\":\"17da0d3a86bd8505daa07e9895643b7de2d2877768fbaf9c8abd8475f8c6bcc2\"},\"base_mac_stage\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/release-evidence-r1/MAC-STAGE-ORIGINAL.json\",\"bytes\":28841,\"sha256\":\"a037b49f05ea48caccb2902b95bbb2314a5f767e230138dd14ae3a16851ee4b2\"},\"base_compiler\":{\"bytes\":42341,\"sha256\":\"51265398de2dcc4ccefb5aa0e24ea91770d8c9f3b54248f3d88068e04a4436cc\"},\"base_build_stdout\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/release-evidence-r1/mac/original-android-native-build.stdout\",\"bytes\":121423,\"sha256\":\"ce47720cad1c09c685657b0d0c801281552cc69a0d15679cb5ffd24ec992e422\"},\"worker\":{\"bytes\":59952,\"sha256\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\"},\"generated_worker_sha256\":\"77b914eae46ea000d3c955628c35f6e96a715a4a14da3eb075923d2e6024bbb0\",\"native_pins\":{\"libMNN.so\":\"5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d\",\"libc++_shared.so\":\"77a34d3f03b17709f3f6473f37cb7795314e51fa3e5e652b5c37d53cfd05c754\",\"libgeniex.so\":\"99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56\",\"libgeniex_plugin_llama_cpp.so\":\"cc186649cc0dab10240395f89d14d007e62b3bc78283060027d37ee80a21604a\",\"libggml-base.so\":\"bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40\",\"libggml-cpu.so\":\"b603d578bb3beb0c3727be748f327c002619827df701bf0b894632272670943b\",\"libggml-hexagon.so\":\"67b886eb9bcdd298268a8463d74f07da4213024fe7ed89911c2e76c9e0d1491f\",\"libggml-htp-v79.so\":\"110d9e6ff7cff02fa73b0a3c03d8259222758934bdbcae5c819dae6729f362d5\",\"libggml-opencl.so\":\"e395cf83e695aa9d21dd90a89460f936742c7c8c706cfbbdfa647dd316dd0875\",\"libggml.so\":\"5dff1d15e528d1accb1704a1049a6556784cbfc32131fb64cef5c8847c171149\",\"libhepta_local_runner.so\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"libhepta_mobimind_runner.so\":\"b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020\",\"libhepta_ui_venus_runner.so\":\"5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551\",\"libllama-common.so\":\"8b05589a739339dd38ad524e9733d89650ef40b0a83fe3a95ff83716c98c6122\",\"libllama.so\":\"4bb7bd0f4fe0bd24ac32a80f920838fd2f525430ad58c5d5742cc745f7d0b835\",\"libmtmd.so\":\"ccf32e264cdccc6378d5e4e005f4aedae39eb3e9a198550c5f7f3a4583bcaa4d\",\"libomp.so\":\"b0b507bb9e89360304272ba335d5fb2f6661f88842c2b3c749474cb7b8acda76\"},\"identity_root\":\"/home/alex/hepta-local-007f-20261111/v55-installed-apk-identity-host-r1\",\"identity_result\":{\"bytes\":5727,\"sha256\":\"52762ada64c63bc58749d62e9bd183b586c40349f0e10082ded1c308d82df4f7\"},\"identity_stage\":{\"bytes\":14247,\"sha256\":\"17f95a5eecf3716c48228c4086e2d428b4e5c2c57c77707116673d92820d9bf8\"},\"identity_input\":{\"bytes\":36100,\"sha256\":\"bfcee1680b7e3c4c0933aed26bfce6320b64ae7803347f3ddfc56616067b8176\"},\"identity_source\":{\"bytes\":9255,\"sha256\":\"e3ca49ba910ff1bb26f50452e1f718313dbce51df9d77c8b107867351178e1d9\"},\"identity_generated\":{\"bytes\":14192,\"sha256\":\"38ec317c6344665e06c73c3c50816cbfa4e96ef3ed69b6a40dd38d525ca26dd7\"},\"focused_root\":\"/home/alex/hepta-local-007f-20261111/v58-main-wire4-host-p4-r1\",\"focused_result\":null,\"focused_input\":{\"bytes\":1313265,\"sha256\":\"784c722634848b0b9baac0d8d430ef24e8d2850964c185737f6de547aa6df593\"},\"focused_stage\":{\"bytes\":79802,\"sha256\":\"a7b9a549983ff21f6c62b47ebb60d6c172c22d42d2d092ede5d726996546b2a7\"},\"calendar_dom\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/release-evidence-r1/fixtures/calendar-stable.json\",\"bytes\":386724,\"sha256\":\"f61fd86cb24b212c3434bb5eda1a4e29b65c06c22d3fc4238366f31a324dd7fa\"},\"calendar_ax\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/release-evidence-r1/fixtures/calendar-stable.xml\",\"bytes\":178888,\"sha256\":\"59d753e32edd620eb2e1fb0947c898df89eb7bf8dbc63dc4138a1636272b82ec\"},\"query_runner\":{\"bytes\":41005,\"sha256\":\"5af6324496884603f2be5184334335e17d59dd653d0dd20ec859d5c064820b10\"},\"jdk\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64\",\"tools\":{\"java\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/java\",\"bytes\":14544,\"sha256\":\"bb70208200cb6538b877d80478141194a716edb591f4910ec106589291e99196\"},\"javac\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/javac\",\"bytes\":14592,\"sha256\":\"2aaf03d13aeb80b8269696f2dcd9f4937d7366bbc68f91fdc703cf157e8f39c4\"},\"json\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-public-inputs-r1/host-json/json-20240303.jar\",\"bytes\":78332,\"sha256\":\"3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed\"},\"android_jar\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-sdk-input-r2/sdk/android-34/android.jar\",\"bytes\":26361808,\"sha256\":\"6cea1df3efb77103ac3e2beb9bf4718964b0e0869ab16d39d29d5cbae1c147ad\"},\"r8\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-public-large-inputs-r1/tools/r8-8.13.17.jar\",\"bytes\":18279079,\"sha256\":\"d31fd0dc751d48740009cdd9a485126acb1d0d14c59b9f05579479940f4adf74\"},\"aapt2\":{\"path\":\"/usr/lib/android-sdk/build-tools/debian/aapt2\",\"bytes\":54512,\"sha256\":\"0e9ff92342040acdfd03e8708512f4e02353e3ca0a2b85ea2950da659110b009\"}},\"sdk_download_root\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-sdk-input-r2\",\"sdk_download_result\":{\"bytes\":64222,\"sha256\":\"5300257b246f73bc410028d8e1e61f18381e6f9b4a4406661d00b7d3d128eab6\"},\"original_aggregate\":{\"git\":\"517e61599073eb264c5e52871570d49e7af2d798\",\"bytes\":1459826,\"sha256\":\"b98bb0f97ad5b25423387c4e3f8734aec7d4f8c2d1044335af039e0dd1c57cc3\"},\"original_decoded_input\":{\"bytes\":1598487,\"sha256\":\"d7174a964b506448c44f627e250cd662d953a94005790aad9ad7297671f5c13d\"},\"original_source_inventory_sha256\":\"22d32f2de9ecd5690e1dfe7de8fa682b3a0469584ade1ec83ac69bf6558d10b6\",\"materialized_root\":\"/home/alex/hepta-local-007f-20261111/v58-main-core101-materialized-host-r1\",\"prior_build_root\":\"/home/alex/hepta-local-007f-20261111/v57-main-p4-android-r1\",\"prior_build_result\":{\"bytes\":244800,\"sha256\":\"5dc739a182bda8065f2bda04c1da7e44c43b74307f76f582ba6cc09c371475f1\"},\"prior_build_stage\":{\"bytes\":113856,\"sha256\":\"ac4b54eb0815bce791a99ae3e01de8077808fe55b5eabc58488fd1eba8126331\",\"git_blob_sha\":\"bd30b22cf1a151710318a1e768be63f7a75b6bd8\"},\"prior_compiler_inputs\":{\"bytes\":34376,\"sha256\":\"54e95d6949154c631302241f76ca3518650ac297166210056f7e2f7740fc4370\"},\"compiler_inputs\":{\"bytes\":34376,\"sha256\":\"b64d1a78f41ffa78c80c3d5145b012f0625e842725ceb83abbd8eec5bb63c4c8\"},\"source_deltas\":[{\"path\":\"AndroidManifest.xml\",\"base\":{\"bytes\":2594,\"sha256\":\"71aca282ccdd9fb1eb4bb611296418f7f80502bcb7a3b9bcdef98460cae13c73\",\"git_blob_sha\":\"92012a454023ca82eaaa0b63384208fb86efb5d4\"},\"candidate\":{\"bytes\":2591,\"sha256\":\"4818f3632b34a1bb6eb41d35e45f0d1d99ed50275da3d999f4a56608b7725b8e\",\"git_blob_sha\":\"10ef60b074dca1cf5d0cf8063054cd9559ca805b\"},\"ordered_patches\":[{\"before\":\"android:versionCode=\\\"57\\\"\",\"after\":\"android:versionCode=\\\"58\\\"\",\"count\":1},{\"before\":\"android:versionName=\\\"0.57.0-flight-observation-stability\\\"\",\"after\":\"android:versionName=\\\"0.58.0-flight-observation-settle\\\"\",\"count\":1}]},{\"path\":\"src/org/trillionnium/hepta/local/WebFlightSession.java\",\"base\":{\"bytes\":44197,\"sha256\":\"07509c1345b1bacdfcbf504943f375869c274e245c6aafb5819581b4c8395408\",\"git_blob_sha\":\"87b2bd6a8758fb6c46659270412bf9d630673591\"},\"candidate\":{\"bytes\":46689,\"sha256\":\"d2e4f073366d3d3046b0f9b90156f87b1fb84c842a3053a5d32f31df5e3bbc9b\",\"git_blob_sha\":\"d89ff1a111693bebd445c99fede473fbc968a314\"},\"ordered_patches\":[{\"before\":\"        WebDomStability.Result domBracket=null;\\n\",\"after\":\"        WebDomStability.Result domBracket=null;String domBracketError=null;\\n\",\"count\":1},{\"before\":\"        }catch(Exception incompleteBracket){\\n            // A changing bracket supplies no action. Existing loading retries\\n            // remain bounded and read-only; no preceding click is repeated.\\n        }\\n\",\"after\":\"        }catch(Exception incompleteBracket){\\n            // No action capability is published from a changing bracket.\\n            domBracketError=incompleteBracket.getClass().getSimpleName()+\\\": \\\"+\\n                    HeptaAccessibilityService.limited(HeptaAccessibilityService.message(incompleteBracket),512);\\n        }\\n\",\"count\":1},{\"before\":\"        if(retryLoadingDocument(first,last,after,stable,deadline)){\\n            loadingAttemptKey=actualLoadingKey;\\n            captureDeadline=Math.min(deadline,loadingDocumentStarted+6000);\\n            before=observer.observe();service.requireBackgroundObservation(taskId,before);\\n            continue;\\n        }\\n        if(!stable&&!sameOriginalFrame&&sameCaptureDomain&&goal!=null&&nativeSource!=null\\n                &&first.stability().rawEqual&&domBracket.rawEqual&&last.stability().rawEqual){\\n            // This service-created proof only admits the new read-only frame.\\n            // A later action still needs its own original model target and live Permit checks.\\n            nativeObservationBracket=service.verifyFlightObservationBracket(this,nativeSource,after,first,last,\\n                    cancellation,captureDeadline);\\n            stable=true;\\n        }\\n\",\"after\":\"        if(!stable&&!sameOriginalFrame&&sameCaptureDomain&&goal!=null&&nativeSource!=null\\n                &&first.stability().rawEqual&&domBracket.rawEqual&&last.stability().rawEqual){\\n            // This service-created proof only admits the new read-only frame.\\n            // A later action still needs its own original model target and live Permit checks.\\n            nativeObservationBracket=service.verifyFlightObservationBracket(this,nativeSource,after,first,last,\\n                    cancellation,captureDeadline);\\n            stable=true;\\n        }\\n        // The retained NodeRef belongs only to this completed read bracket.\\n        // Release it before a wait or a fresh observation replaces the graph.\\n        if(nativeSource!=null){nativeSource.close();nativeSource=null;}\\n        if(retryLoadingDocument(first,last,before,after,stable,sameCaptureDomain,domBracketError,deadline)){\\n            loadingAttemptKey=actualLoadingKey;\\n            captureDeadline=Math.min(deadline,loadingDocumentStarted+6000);\\n            before=observer.observe();service.requireBackgroundObservation(taskId,before);\\n            continue;\\n        }\\n\",\"count\":1},{\"before\":\"    private boolean retryLoadingDocument(WebEvidenceReceipt first,WebEvidenceReceipt last,PhoneObservation frame,\\n                                         boolean stable,long deadline)throws Exception{\\n\",\"after\":\"    private boolean retryLoadingDocument(WebEvidenceReceipt first,WebEvidenceReceipt last,\\n                                         PhoneObservation before,PhoneObservation frame,boolean stable,\\n                                         boolean sameCaptureDomain,String domBracketError,long deadline)throws Exception{\\n\",\"count\":1},{\"before\":\"        if(!bodyPending&&!bookingPending&&!queryPending&&!(key.equals(loadingDocumentKey)&&!stable))return false;\\n\",\"after\":\"        if(!bodyPending&&!bookingPending&&!queryPending&&stable)return false;\\n\",\"count\":1},{\"before\":\"        if(loadingDocumentReadRetries>=2||now+250>=Math.min(deadline,loadingDocumentStarted+6000))return false;\\n        need(!retired&&!cancellation.isCancelled(),\\\"web task retired while waiting for page content\\\");\\n        loadingDocumentReadRetries++;\\n\",\"after\":\"        boolean retry=loadingDocumentReadRetries<2&&now+250<Math.min(deadline,loadingDocumentStarted+6000);\\n        if(!retry&&stable)return false;\\n        need(!retired&&!cancellation.isCancelled(),\\\"web task retired while waiting for page content\\\");\\n        // A new read cannot reuse an earlier page, node permit or dispatch check.\\n        // Keep model-run attempted fences and the actual flight progress unchanged.\\n        domain=null;current=null;currentCapture=null;flightNativePermit=null;flightNativeCheck=null;\\n        dispatchSource=null;dispatchSourceRun=null;dispatchSourceAction=null;\\n        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;shoppingDispatch=null;\\n        completion.clearWebDomain();\\n        if(retry)loadingDocumentReadRetries++;\\n\",\"count\":1},{\"before\":\"                .put(\\\"actual_query_awaiting_results\\\",queryPending).put(\\\"read_only_retry\\\",loadingDocumentReadRetries)\\n                .put(\\\"maximum_extra_reobservations\\\",2).put(\\\"deadline_elapsed_ms\\\",Math.min(deadline,loadingDocumentStarted+6000))\\n                .put(\\\"action_replayed\\\",false).put(\\\"model_action_dispatched\\\",false).put(\\\"business_verified\\\",false));\\n        SystemClock.sleep(200);\\n\",\"after\":\"                .put(\\\"actual_query_awaiting_results\\\",queryPending).put(\\\"read_only_retry\\\",loadingDocumentReadRetries)\\n                .put(\\\"maximum_extra_reobservations\\\",2).put(\\\"deadline_elapsed_ms\\\",Math.min(deadline,loadingDocumentStarted+6000))\\n                .put(\\\"reason\\\",stable?\\\"recognized_content_pending\\\":\\\"unstable_ax_dom_bracket\\\")\\n                .put(\\\"reobserve_scheduled\\\",retry).put(\\\"read_only_budget_exhausted\\\",!retry)\\n                .put(\\\"first_ax_observation_id\\\",before.id).put(\\\"last_ax_observation_id\\\",frame.id)\\n                .put(\\\"first_ax_tree_sha256\\\",before.treeSha256).put(\\\"last_ax_tree_sha256\\\",frame.treeSha256)\\n                .put(\\\"first_ax_app_tree_sha256\\\",before.state.appTreeSha256).put(\\\"last_ax_app_tree_sha256\\\",frame.state.appTreeSha256)\\n                .put(\\\"first_ax_window_id\\\",before.windowId).put(\\\"last_ax_window_id\\\",frame.windowId)\\n                .put(\\\"first_ax_rotation\\\",before.rotation).put(\\\"last_ax_rotation\\\",frame.rotation)\\n                .put(\\\"first_ax_display_id\\\",before.windowMetadata.displayId).put(\\\"last_ax_display_id\\\",frame.windowMetadata.displayId)\\n                .put(\\\"first_background_generation\\\",before.backgroundGeneration).put(\\\"last_background_generation\\\",frame.backgroundGeneration)\\n                .put(\\\"same_original_frame\\\",sameFrame(before,frame)).put(\\\"same_capture_domain\\\",sameCaptureDomain)\\n                .put(\\\"dom_bracket_error\\\",domBracketError==null?JSONObject.NULL:domBracketError)\\n                .put(\\\"first_navigation_epoch\\\",first.epoch).put(\\\"last_navigation_epoch\\\",last.epoch)\\n                .put(\\\"first_native_url\\\",first.url).put(\\\"last_native_url\\\",last.url)\\n                .put(\\\"old_action_capabilities_retired\\\",true)\\n                .put(\\\"action_replayed\\\",false).put(\\\"model_action_dispatched\\\",false).put(\\\"business_verified\\\",false));\\n        if(!retry)return false;\\n        SystemClock.sleep(200);\\n\",\"count\":1}]}],\"exact_changed_paths\":[\"AndroidManifest.xml\",\"src/org/trillionnium/hepta/local/WebFlightSession.java\"],\"source_inventory_bytes\":103795,\"query_java_source_count\":50,\"predecessor_release\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v57-main-sign-r1/RESULT.json\",\"bytes\":35104,\"sha256\":\"9deb86d5ba6b066bf250a432559bdc1fcee1138596af3f40133943c6259dd60c\"},\"predecessor_release_source_commit\":\"313685edc580a750aea6301d8ff3cfd617d6fab6\",\"predecessor_apk\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v57-main-sign-r1/out/hepta-local-0.57.0.apk\",\"bytes\":21038933,\"sha256\":\"c1e126031ff8728a3335a5ef1e6d546b3b089ca03ee73a8b3671b67b7e124ad4\"},\"version_code\":58,\"version_name\":\"0.58.0-flight-observation-settle\",\"candidate_scope\":\"bounded fresh read-only observation settling under unchanged original task/lease/window/epoch/geometry guards; no action replay; Flight results provider remains false\",\"query_case_expectation\":{\"cases\":40,\"assertions\":187,\"case_names\":[\"literal_city_data_is_not_a_verified_route\",\"matching_form_without_model_actions_cannot_query\",\"real_class_selection_chain_enables_exact_query_once\",\"accepted_picker_click_waits_for_native_form_readback\",\"false_city_outcome_never_confirms\",\"stale_city_outcome_never_confirms\",\"date_before_two_city_confirmations_withheld\",\"wrong_after_city_literal_stays_pending\",\"dom_city_without_same_native_value_stays_pending\",\"foreign_native_city_descendant_rejected\",\"two_cities_without_full_calendar_date_cannot_query\",\"wrong_after_month_day_stays_pending\",\"wrong_after_weekday_stays_pending\",\"date_before_dispatch_end_cannot_confirm\",\"later_route_change_invalidates_current_query\",\"later_date_change_invalidates_year_confirmation\",\"native_field_disappears_query_withheld\",\"two_adults_are_not_one_adult_query\",\"disabled_dom_query_cannot_mint_target\",\"duplicate_native_query_even_disabled_refuses\",\"another_binding_cannot_import_selection_chain\",\"navigation_epoch_regression_cannot_import_progress\",\"query_reservation_is_not_a_dispatch\",\"second_query_reservation_refused\",\"actual_query_outcome_and_after_capture_remain_not_results\",\"false_query_outcome_consumes_attempt\",\"accepted_query_without_platform_entry_refused\",\"query_outcome_before_capture_refused\",\"query_outcome_wrong_model_run_refused\",\"query_outcome_twice_refused\",\"unknown_booking_body_is_read_only_pending\",\"city_airport_combination_not_silently_normalized\",\"actual_session_dispatch_methods_0\",\"actual_session_dispatch_methods_1\",\"actual_session_dispatch_methods_2\",\"actual_session_dispatch_methods_3\",\"actual_session_dispatch_methods_4\",\"actual_session_dispatch_methods_5\",\"actual_session_dispatch_methods_6\",\"actual_session_dispatch_methods_7\"]},\"query_runner_integrated_into_source\":true}")

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
    baseline=case_summary(previous,label+" signed57 baseline")
    old_names=set(baseline["case_names"])
    need(target["cases"] >= baseline["cases"] and target["assertions"] >= baseline["assertions"]
         and [name for name in target["case_names"] if name in old_names]==baseline["case_names"],
         label+": all actual57 case names retained in original relative order")
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


def prior_artifact_paths(root):
    need(root.is_dir() and not root.is_symlink(), "existing original build root")
    names = []
    for path in sorted(root.rglob("*")):
        need(not path.is_symlink(), "no original build symlink")
        if path.is_dir():
            continue
        names.append(relative(path.relative_to(root).as_posix()))
        need(len(names) <= 4096, "bounded original build file count")
    return names

def preserve_prior_build(root, original_facts):
    facts, total = {}, 0
    for name in prior_artifact_paths(root):
        raw, item = read_regular(root/name)
        total += len(raw)
        need(total <= 256<<20, "bounded original build total bytes")
        facts[name] = item
        original_facts.append(item)
    return facts

def reviewed_source_successor(prior_source, target):
    need(set(prior_source).issubset(target), "no predecessor source member may disappear")
    changed = sorted(name for name in target if name not in prior_source or target[name] != prior_source[name])
    need(changed == CONFIG["exact_changed_paths"]
         and [row["path"] for row in CONFIG["source_deltas"]] == changed,
         "only the complete explicitly reviewed source delta")
    for delta in CONFIG["source_deltas"]:
        name = relative(delta["path"])
        need(name == "AndroidManifest.xml"
             or (name.startswith("src/") and name.endswith(".java"))
             or (name.startswith("tests/") and name.endswith((".java",".py")))
             or name in ("tests/qualification-scope/ServiceFixture.template",
                         "tests/qualification-scope/BackgroundObservationFixture.template"),
             "this successor changes only the manifest, Java, or explicit test fixtures")
        new_raw = checked(target[name], delta["candidate"], "complete sealed successor source")
        if delta["base"] is None:
            need(name not in prior_source and name.startswith("src/") and name.endswith(".java")
                 and set(delta) == {"path","base","candidate","raw_utf8"}
                 and type(delta["raw_utf8"]) is str
                 and delta["raw_utf8"].encode("utf-8","strict") == new_raw,
                 "one explicitly sealed new Java member, never an implicit replacement")
            continue
        need(name in prior_source and set(delta) == {"path","base","candidate","ordered_patches"}
             and type(delta["ordered_patches"]) is list and len(delta["ordered_patches"]) > 0,
             "complete replacement source delta")
        old_raw = checked(prior_source[name], delta["base"], "original signed57 source")
        current = old_raw.decode("utf-8","strict")
        for patch in delta["ordered_patches"]:
            need(set(patch) == {"before","after","count"} and type(patch["count"]) is int
                 and patch["count"] == 1 and type(patch["before"]) is str and patch["before"] != ""
                 and type(patch["after"]) is str and patch["after"] != ""
                 and current.count(patch["before"]) == 1, "exact source successor patch")
            current = current.replace(patch["before"], patch["after"], 1)
        need(current.encode("utf-8","strict") == new_raw, "full successor bytes equal reviewed replacement")
        for patch in reversed(delta["ordered_patches"]):
            need(current.count(patch["after"]) == 1, "unique inverse source patch")
            current = current.replace(patch["after"], patch["before"], 1)
        need(current.encode("utf-8","strict") == old_raw, "exact inverse signed57 source restoration")

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


def build_unsigned(base_raw,dex_raw,build_asset):
    expected_base={"AndroidManifest.xml","resources.arsc","res/xml/hepta_accessibility_service.xml"}
    with zipfile.ZipFile(io.BytesIO(base_raw)) as base:
        need(len(base.infolist()) == len(set(base.namelist())) and set(base.namelist()) == expected_base,
             "exact current aapt2 resource member set")
        payloads={name:base.read(name) for name in sorted(expected_base)}
    need(dex_raw[:4] == b"dex\n", "actual compiled DEX magic")
    payloads["classes.dex"]=dex_raw
    payloads["assets/hepta-build-identity.json"]=build_asset
    payloads.update(native_payloads)
    path=OUT/"hepta-local-0.57.0-unsigned.apk"
    with zipfile.ZipFile(path,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        # Source-commit publication is intentionally absent until the separately
        # reviewed final source/host CAS and signer operation.
        for name in ["assets/hepta-build-identity.json"]+sorted(n for n in payloads if n!="assets/hepta-build-identity.json"):
            item=zipfile.ZipInfo(name,(2026,11,12,0,0,0))
            item.compress_type=zipfile.ZIP_STORED if name=="resources.arsc" else zipfile.ZIP_DEFLATED
            item.external_attr=((0o100755 if name.startswith("lib/") else 0o100644)<<16)
            if name=="resources.arsc":
                padding=(-(archive.fp.tell()+30+len(name.encode("utf-8"))+4))%4
                item.extra=struct.pack("<HH",0xffff,padding)+b"\0"*padding
            archive.writestr(item,payloads[name],compress_type=item.compress_type,compresslevel=6)
    raw,facts=read_regular(path)
    layout=None
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        need(len(archive.infolist())==len(payloads) and set(archive.namelist())==set(payloads)
             and len(archive.namelist())==len(set(archive.namelist())), "exact unsigned APK members")
        need(archive.testzip() is None, "all unsigned APK CRCs")
        for member in archive.infolist():
            need(not member.is_dir() and archive.read(member.filename)==payloads[member.filename],
                 "every actual unsigned payload preserved")
            at=member.header_offset
            need(raw[at:at+4]==b"PK\x03\x04", "actual local ZIP header")
            local_method=struct.unpack_from("<H",raw,at+8)[0]
            name_len,extra_len=struct.unpack_from("<HH",raw,at+26)
            actual_name=raw[at+30:at+30+name_len]
            need(actual_name==member.filename.encode("utf-8") and local_method==member.compress_type,
                 "local/central method and name agree")
            if member.filename=="resources.arsc":
                offset=at+30+name_len+extra_len
                need(local_method==zipfile.ZIP_STORED and offset%4==0,
                     "actual resources STORED and4-byte aligned")
                layout={"compression_method":0,"local_data_offset":offset,"four_byte_aligned":True,
                        "payload_sha256":sha(payloads[member.filename])}
            elif member.filename.startswith("lib/"):
                need(local_method==zipfile.ZIP_DEFLATED
                     and sha(archive.read(member.filename))==CONFIG["native_pins"][Path(member.filename).name],
                     "all17 extracted native payloads remain exact")
    need(layout is not None and len(payloads)==22, "complete current unsigned main APK")
    return facts,layout,[{"path":name,"bytes":len(value),"sha256":sha(value)} for name,value in sorted(payloads.items())]

def current_query40():
    path=SOURCE/"tests/web-flight/run_query_host_tests.py"
    raw=read_regular(path,CONFIG["query_runner"])[0]
    namespace={"__name__":"hepta_exact_query40_runner","__file__":str(path)}
    exec(compile(raw,str(path),"exec",dont_inherit=True),namespace)
    saved_argv=sys.argv
    begin=time.monotonic()
    try:
        sys.argv=[str(path),"--source",str(SOURCE),"--output",str(ROOT/"query40"),
                  "--java-home",CONFIG["jdk"],"--json-jar",CONFIG["tools"]["json"]["path"],
                  "--calendar-dom",CONFIG["calendar_dom"]["path"],"--calendar-ax",CONFIG["calendar_ax"]["path"]]
        code=namespace["main"]()
    finally:
        sys.argv=saved_argv
    report_raw,report_facts=read_regular(ROOT/"query40/RESULT.json")
    report=strict(report_raw)
    need(type(code) is int and code==0 and report["schema"]=="hepta.v55-flight-query-compiled-gate.v1"
         and report["all_pass"] is True and report["originals_unchanged"] is True
         and report["java_source_count"]==CONFIG["query_java_source_count"]
         and case_summary(report["cases"],"actual query")==CONFIG["query_case_expectation"]
         and report["full_selection_provenance_covered_here"] is False
         and report["original_80_43_13_mains_rerun"] is False and report["frozen_39_gate_rerun"] is False
         and report["cases"]["actual_query_executed"] is False and report["cases"]["actual_results_verified"] is False
         and type(report["phone_actions"]) is int and report["phone_actions"]==0,
         "actual reviewed query successor cases without phone or business scope promotion")
    need([r["name"] for r in report["steps"]]==["javac","query-chain"]
         and all(type(r["exit_code"]) is int and r["exit_code"]==0 and r["forced"] is False
                 and r["exception"] is None and r["cleanup_errors"]==[] for r in report["steps"]),
         "query runner's two owned JVM children exited normally")
    for step in report["steps"]:
        for suffix in ("stdout","stderr"):
            payload,_=read_regular(ROOT/"query40"/(step["name"]+"."+suffix))
            need(sha(payload)==step[suffix+"_sha256"], "actual query log full SHA")
    return {"elapsed_seconds":time.monotonic()-begin,"original":report_facts,"report":report,
            "runner_sha256":sha(raw),"runner_path":str(path),
            "runner_original_source_path":"tests/web-flight/run_query_host_tests.py",
            "runner_original_sha256":sha(query_runner_raw),
            "runner_count_adapter":None,
            "runner_corrected_outside_source_tree":False,"repository_runner_count_guard_known_incompatible":False,
            "runner_count_repair_integrated_into_current_source":True,
            "historical_prior_external_runner":prior_build["query40"]["historical_prior_external_runner"],
            "historical_prior_integrated_runner":prior_build["query40"],
            "executed_in_process":True,"owned_child_groups_managed_by_original_runner":True}


# Pending future source pins reject before any filesystem claim or child.
case_expectation(CONFIG["query_case_expectation"],"query successor")
for name in ("aggregate","decoded_input","compiler_inputs","query_runner"):
    value = CONFIG[name]
    need(type(value) is dict and type(value.get("bytes")) is int and value["bytes"] > 0
         and type(value.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}",value["sha256"]),
         "sealed main58 candidate artifact required: "+name)
need(type(CONFIG["aggregate"].get("git")) is str
     and re.fullmatch(r"[0-9a-f]{40}",CONFIG["aggregate"]["git"]), "sealed aggregate Git identity")
for name in ("source_file_count","overlay_file_count","compiler_input_count","java_source_count",
             "source_inventory_bytes","query_java_source_count"):
    need(type(CONFIG[name]) is int and CONFIG[name] > 0, "sealed candidate count required: "+name)
need(type(CONFIG["source_inventory_sha256"]) is str
     and re.fullmatch(r"[0-9a-f]{64}",CONFIG["source_inventory_sha256"]),
     "sealed complete successor inventory SHA")
need(type(CONFIG["exact_changed_paths"]) is list and len(CONFIG["exact_changed_paths"]) > 0
     and all(type(name) is str for name in CONFIG["exact_changed_paths"])
     and CONFIG["exact_changed_paths"] == sorted(set(CONFIG["exact_changed_paths"]))
     and "AndroidManifest.xml" in CONFIG["exact_changed_paths"]
     and type(CONFIG["source_deltas"]) is list
     and len(CONFIG["source_deltas"]) == len(CONFIG["exact_changed_paths"]),
     "reviewed explicit version and provider source delta required")

# A completed actual focused39 proof is required. Pending pins reject before mutation.
for name in ("focused_result","focused_stage","focused_input"):
    need(type(CONFIG[name]) is dict and type(CONFIG[name].get("bytes")) is int and CONFIG[name]["bytes"] > 0
         and re.fullmatch(r"[0-9a-f]{64}", CONFIG[name].get("sha256", "")),
         "actual Pocket4 focused39 complete pin required: "+name)
need(type(CONFIG["sdk_download_result"]) is dict and type(CONFIG["sdk_download_result"].get("bytes")) is int
     and re.fullmatch(r"[0-9a-f]{64}", CONFIG["sdk_download_result"].get("sha256", "")),
     "actual completed SDK archive-only RESULT pins required")
stage_raw = globals().get("__stage_source__")
need(type(stage_raw) is bytes and len(stage_raw) > 0, "exact hashed stage bytes required")
ROOT = Path(CONFIG["root"])
BASE = Path(CONFIG["base_root"])
SOURCE, OUT, FOCUSED = ROOT/"source", ROOT/"out", Path(CONFIG["focused_root"])
need(sys.platform == "linux", "explicit Pocket4 Linux build")
need(ROOT.is_absolute() and not ROOT.exists() and not ROOT.is_symlink(), "new exclusive build root")
original_facts = []
PRIOR_BUILD = Path(CONFIG["prior_build_root"])
original_input_raw = load_bound(PRIOR_BUILD/"INPUT.json", CONFIG["original_decoded_input"], original_facts)
original_data = strict(original_input_raw)
need(original_data["schema"] == "hepta.main57-pocket4-java-android-input.v1",
     "actual completed57 full input is the immutable predecessor")
shared_aggregate_raw = load_bound(PRIOR_BUILD/"AGGREGATE.json", CONFIG["original_aggregate"], original_facts)
need(blob(shared_aggregate_raw) == CONFIG["original_aggregate"]["git"]
     and original_data["aggregate_raw_utf8"].encode("utf-8","strict") == shared_aggregate_raw,
     "actual signed57 aggregate and original full input agree")
MATERIALIZED = Path(CONFIG["materialized_root"])
materialized_aggregate_raw = load_bound(MATERIALIZED/"AGGREGATE.json", CONFIG["aggregate"], original_facts)
need(blob(materialized_aggregate_raw) == CONFIG["aggregate"]["git"], "materialized successor aggregate Git identity")
materialized_compiler_raw = load_bound(MATERIALIZED/"COMPILER-INPUTS.json", CONFIG["compiler_inputs"], original_facts)
materialized_compiler = strict(materialized_compiler_raw)
need(type(materialized_compiler) is list
     and len(materialized_compiler) == CONFIG["compiler_input_count"]
     and len({row["path"] for row in materialized_compiler}) == len(materialized_compiler),
     "complete distinct materialized successor compiler input map")
data = strict(original_input_raw)
data["schema"] = "hepta.main58-pocket4-java-android-input.v1"
data["aggregate_raw_utf8"] = materialized_aggregate_raw.decode("utf-8","strict")
data["expected_compiler_inputs"] = materialized_compiler
checked(encoded(original_data["expected_compiler_inputs"]), CONFIG["prior_compiler_inputs"], "actual57 compiler map")
checked(encoded(materialized_compiler), CONFIG["compiler_inputs"], "sealed successor compiler map")
old_compiler = {row["path"]:row["sha256"] for row in original_data["expected_compiler_inputs"]}
new_compiler = {row["path"]:row["sha256"] for row in materialized_compiler}
need(set(old_compiler).issubset(new_compiler), "no original compiler input removed")
compiler_changed_paths = sorted(name for name in new_compiler
                                if name not in old_compiler or new_compiler[name] != old_compiler[name])
need(compiler_changed_paths
     and set(compiler_changed_paths).issubset(CONFIG["exact_changed_paths"]),
     "all changed or added compiler members are explicitly reviewed source deltas")
input_raw = checked(encoded(data), CONFIG["decoded_input"], "complete successor build input from actual57 bytes")
data = strict(input_raw)
need(data["schema"] == "hepta.main58-pocket4-java-android-input.v1"
     and data["claims"] == {"signed": False, "published": False, "phone_actions": 0, "business_verified": False},
     "unsigned host-only input scope")
need(data["native_reuse_authorization"] == {
    "scope":"actual Java/DEX/resources compile; preserve all17 signed54 native payloads byte-identically",
    "native_recompiled_here":False,"original_native_build_script_unmodified":True,"results_provider_ready":False},
    "explicit source-only native reuse and results-provider boundary")
aggregate_raw = data["aggregate_raw_utf8"].encode("utf-8", "strict")
checked(aggregate_raw, CONFIG["aggregate"], "complete reviewed aggregate")
need(blob(aggregate_raw) == CONFIG["aggregate"]["git"], "aggregate Git blob")
aggregate = strict(aggregate_raw)
need(aggregate["base_source_commit"] == CONFIG["base_source_commit"]
     and aggregate["base_source_inventory_sha256"] == CONFIG["base_source_inventory_sha256"]
     and aggregate["compiled"] is False and aggregate["signed"] is False and aggregate["published"] is False,
     "unpublished source candidate derived from signed54")
before, before_facts = snapshot(BASE/"source")
validate_map(before, aggregate["base_files"], True)
need(len(before) == 589 and sha(encoded(rows(before))) == CONFIG["base_source_inventory_sha256"],
     "actual complete signed54 source tree")
original_facts.extend(before_facts.values())
target = dict(before)
need(len(aggregate["files"]) == CONFIG["overlay_file_count"]
     and len({row["path"] for row in aggregate["files"]}) == CONFIG["overlay_file_count"], "exact reviewed overlay count")
for item in aggregate["files"]:
    name = relative(item["path"])
    raw = item["raw_utf8"].encode("utf-8", "strict")
    checked(raw, item, "overlay full bytes")
    need(blob(raw) == item["git_blob_sha"], "overlay Git identity")
    if item["base"] is None:
        need(name not in target, "new source cannot replace an old path")
    else:
        need(name in target, "replacement source must exist")
        checked(target[name], item["base"], "exact signed54 overlay base")
        need(blob(target[name]) == item["base"]["git_blob_sha"], "original overlay base Git")
    target[name] = raw
validate_map(target, aggregate["inventory"]["files"], True)
need(len(target) == CONFIG["source_file_count"]
     and sha(encoded(rows(target))) == CONFIG["source_inventory_sha256"], "complete sealed successor source tree")
PRIOR_BUILD = Path(CONFIG["prior_build_root"])
prior_build_raw = load_bound(PRIOR_BUILD/"RESULT.json", CONFIG["prior_build_result"], original_facts)
prior_build = strict(prior_build_raw)
need(prior_build["schema"] == "hepta.main57-pocket4-java-native-reuse-stage.v1"
     and prior_build["root"] == str(PRIOR_BUILD)
     and prior_build["all_pass"] is True and type(prior_build["exit_code"]) is int
     and prior_build["exit_code"] == 0 and prior_build["originals_unchanged"] is True
     and prior_build["written_files_unchanged"] is True and prior_build["current_source_unchanged"] is True
     and prior_build["android_java_compiled_here"] is True and prior_build["native_recompiled_here"] is False
     and prior_build["native_payloads_reused_from_signed54"] is True
     and prior_build["signed"] is False and prior_build["published"] is False
     and prior_build["phone_actions"] == 0 and prior_build["business_verified"] is False,
     "the original signed57 Android build is preserved as its actual successful result")
need(prior_build["source_candidate_git"] == CONFIG["original_aggregate"]["git"]
     and prior_build["source_inventory_sha256"] == CONFIG["original_source_inventory_sha256"]
     and prior_build["source_inputs"] == original_data["expected_compiler_inputs"]
     and prior_build["stage_sha256"] == CONFIG["prior_build_stage"]["sha256"]
     and prior_build["input_sha256"] == CONFIG["original_decoded_input"]["sha256"],
     "original signed57 Android result remains bound to its own source")
need([step["name"] for step in prior_build["steps"]] ==
     ["javac","d8","aapt2-compile","aapt2-link","badging","permissions","manifest","accessibility"]
     and all(type(step["exit_code"]) is int and step["exit_code"] == 0
             and step["timed_out"] is False and step["forced_kill"] is False
             and step["exit_observed"] is True for step in prior_build["steps"])
     and prior_build["query40"]["report"]["all_pass"] is True
     and prior_build["query40"]["report"]["cases"]["cases"] == 40,
     "preserve the eight normal exits and actual query40; no new tests claimed")
need(load_bound(PRIOR_BUILD/"stage.py", CONFIG["prior_build_stage"], original_facts)
     and load_bound(PRIOR_BUILD/"INPUT.json", CONFIG["original_decoded_input"], original_facts) == original_input_raw
     and load_bound(PRIOR_BUILD/"AGGREGATE.json", CONFIG["original_aggregate"], original_facts) == shared_aggregate_raw,
     "original signed57 Android stage and exact inputs")
prior_source, prior_source_facts = snapshot(PRIOR_BUILD/"source")
validate_map(prior_source, strict(shared_aggregate_raw)["inventory"]["files"], True)
need(sha(encoded(rows(prior_source))) == CONFIG["original_source_inventory_sha256"],
     "original complete595 source identity")
reviewed_source_successor(prior_source, target)
prior_tree_facts = preserve_prior_build(PRIOR_BUILD, original_facts)
for key in ("compiler_receipt", "unsigned_apk"):
    item = prior_build[key]
    need(Path(item["path"]).parent == PRIOR_BUILD/"out"
         and type(item["bytes"]) is int and item["bytes"] > 0, "fixed prior build artifact")
    load_bound(item["path"], item, original_facts)
for step in prior_build["steps"]:
    for key in ("stdout","stderr"):
        item = step[key]
        need(Path(item["path"]).parent == PRIOR_BUILD, "fixed prior step log")
        load_bound(item["path"], item, original_facts)
prior_query = prior_build["query40"]["original"]
need(Path(prior_query["path"]) == PRIOR_BUILD/"query40/RESULT.json", "fixed prior query receipt")
need(strict(load_bound(prior_query["path"], prior_query, original_facts)) == prior_build["query40"]["report"],
     "complete original query40 receipt")
require_case_successor(CONFIG["query_case_expectation"],prior_build["query40"]["report"]["cases"],"query successor")
materialized_inventory_raw = load_bound(MATERIALIZED/"SOURCE-INVENTORY.json",
    {"bytes":CONFIG["source_inventory_bytes"],"sha256":CONFIG["source_inventory_sha256"]}, original_facts)
need(materialized_inventory_raw == encoded(rows(target)), "same complete source inventory as the successor core materialization")
materialized_source, materialized_source_facts = snapshot(MATERIALIZED/"source")
need(materialized_source == target, "compile the same complete materialized source as core and Web regression")
original_facts.extend(materialized_source_facts.values())

release_raw = load_bound(CONFIG["predecessor_release"]["path"], CONFIG["predecessor_release"], original_facts)
release = strict(release_raw)
need(release["schema"] == "hepta.isolated-v57-assembly.v1" and release["all_pass"] is True
     and type(release["exit_code"]) is int and release["exit_code"] == 0
     and release["version_code"] == 57
     and release["source_commit"] == CONFIG["predecessor_release_source_commit"]
     and release["source_inventory_sha256"] == CONFIG["original_source_inventory_sha256"]
     and release["pocket4_build_result_sha256"] == CONFIG["prior_build_result"]["sha256"]
     and release["compiled_and_published_source_byte_identical"] is True
     and release["source_files_unchanged"] is True
     and release["apk_sha256"] == CONFIG["predecessor_apk"]["sha256"]
     and release["apk_bytes"] == CONFIG["predecessor_apk"]["bytes"]
     and release["signer_certificate_sha256"] == "202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5"
     and release["library_pins"] == CONFIG["native_pins"],
     "actual signed57 release, exact Android input and native predecessor")
load_bound(CONFIG["predecessor_apk"]["path"], CONFIG["predecessor_apk"], original_facts)

for unchanged_name in ("build_mac.py", "assemble_pocket4.py", "tools/build_identity.py"):
    need(target[unchanged_name] == before[unchanged_name], "original build/assembly/identity implementation preserved")
identity_ns = {"__name__": "hepta_exact_build_identity", "__file__": str(BASE/"source/tools/build_identity.py")}
exec(compile(before["tools/build_identity.py"], identity_ns["__file__"], "exec"), identity_ns)
base_compiler_inputs = identity_ns["source_inputs"](BASE/"source")
need(len(base_compiler_inputs) == 211, "actual baseline compiler input count")
signed_raw = load_bound(CONFIG["base_signed_result"]["path"], CONFIG["base_signed_result"], original_facts)
need(signed_raw == data["base_signed_result_raw_utf8"].encode("utf-8"), "exact reviewed signed54 result")
signed = strict(signed_raw)
need(signed["schema"] == "hepta.isolated-v54-assembly.v1" and signed["all_pass"] is True
     and type(signed["version_code"]) is int and signed["version_code"] == 54
     and signed["source_commit"] == CONFIG["base_source_commit"] and signed["source_file_count"] == 589
     and signed["source_inventory_sha256"] == CONFIG["base_source_inventory_sha256"]
     and signed["apk_sha256"] == CONFIG["base_apk"]["sha256"]
     and signed["apk_bytes"] == CONFIG["base_apk"]["bytes"]
     and signed["signer_certificate_sha256"] == "202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5"
     and signed["library_pins"] == signed["unchanged_native_library_pins"] == CONFIG["native_pins"]
     and signed["packaged_library_count"] == signed["unchanged_native_library_count"] == 17
     and signed["native_libraries_identical_to_formal_v53"] is True,
     "actual signed54 native baseline")
old_apk_raw = load_bound(CONFIG["base_apk"]["path"], CONFIG["base_apk"], original_facts)
archive_raw = load_bound(CONFIG["base_archive"]["path"], CONFIG["base_archive"], original_facts)
mac_stage_raw = load_bound(CONFIG["base_mac_stage"]["path"], CONFIG["base_mac_stage"], original_facts)
mac_stage = strict(mac_stage_raw)
need(mac_stage["all_pass"] is True and type(mac_stage["exit_code"]) is int and mac_stage["exit_code"] == 0
     and mac_stage["android_compiled"] is True and mac_stage["native_compiled"] is True
     and mac_stage["compiler_input_count"] == 211 and mac_stage["source_file_count"] == 589
     and mac_stage["actual_new_native_worker_sha256"] == CONFIG["worker"]["sha256"]
     and mac_stage["native_worker_changed"] is False, "actual prior Android/native compilation")
members = {}
expected_members = {"out/base.apk", "out/dex/classes.dex", "out/libhepta_local_runner.so",
                    "out/mac-build-receipt.json", "out/worker-appuid.c", "out/native-sha256-disassembly.txt"}
with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:gz") as archive:
    for member in archive.getmembers():
        need(member.name in expected_members and member.name not in members and member.isfile()
             and 0 <= member.size <= 16<<20, "exact ordinary six-member original archive")
        stream = archive.extractfile(member)
        need(stream is not None, "original archive content")
        with stream:
            raw = stream.read(member.size+1)
        need(len(raw) == member.size, "complete original archive member")
        members[member.name] = raw
need(set(members) == expected_members, "complete six-member original archive")
prior_compiler_raw = checked(members["out/mac-build-receipt.json"], CONFIG["base_compiler"], "actual compiler receipt")
prior = strict(prior_compiler_raw)
need(prior["schema"] == "hepta.local-model.mac-build.v2" and prior["source_inputs"] == base_compiler_inputs
     and prior["build_host_platform"] == "darwin" and prior["source_head_from_ci"] is None
     and prior["java_target"] == 8 and prior["compile_sdk"] == 34 and prior["target_sdk"] == 35
     and prior["min_sdk"] == 30 and prior["worker_adapter"] == mac_stage["worker_adapter"],
     "exact baseline compiler/source/native adapter binding")
for row in prior["artifacts"]:
    name = {"base.apk":"out/base.apk", "classes.dex":"out/dex/classes.dex",
            "libhepta_local_runner.so":"out/libhepta_local_runner.so"}.get(Path(row["path"]).name)
    need(name in expected_members, "original compiled artifact name")
    checked(members[name], row, "original compiled artifact")
need(len(prior["artifacts"]) == 3
     and {Path(r["path"]).name for r in prior["artifacts"]} == {"base.apk","classes.dex","libhepta_local_runner.so"},
     "exact three original compiled outputs")
checked(members["out/libhepta_local_runner.so"], CONFIG["worker"], "actual unchanged native worker")
need(sha(members["out/worker-appuid.c"]) == CONFIG["generated_worker_sha256"]
     == prior["worker_adapter"]["adapted_sha256"]
     and sha(members["out/native-sha256-disassembly.txt"]) == prior["sha256_instruction_gate"]["disassembly_sha256"]
     and prior["sha256_instruction_gate"]["verified_actual_android_elf"] is True
     and prior["sha256_instruction_gate"]["global_crypto_flag"] is False,
     "original generated worker and actual ELF instruction evidence")
native_build_stdout = load_bound(CONFIG["base_build_stdout"]["path"], CONFIG["base_build_stdout"], original_facts)
native_commands = [line for line in native_build_stdout.decode("utf-8", "strict").splitlines()
                   if line.startswith("RUN ") and "aarch64-linux-android30-clang" in line]
need(len(native_commands) == 1, "one actual original native compiler command")
native_payloads, native_rows = {}, []
with zipfile.ZipFile(io.BytesIO(old_apk_raw)) as archive:
    need(len(archive.infolist()) == len(set(archive.namelist())), "unique signed baseline APK members")
    names = {name for name in archive.namelist() if name.startswith("lib/")}
    need(names == {"lib/arm64-v8a/"+name for name in CONFIG["native_pins"]}, "exact17 original native paths")
    for name in sorted(CONFIG["native_pins"]):
        path = "lib/arm64-v8a/"+name
        info = archive.getinfo(path)
        need(info.compress_type == zipfile.ZIP_DEFLATED and 20 <= info.file_size <= 256<<20,
             "original extracted-native packaging and bounded ELF")
        raw = archive.read(path)
        need(len(raw) == info.file_size and sha(raw) == CONFIG["native_pins"][name],
             "full signed54 native payload hash")
        need(raw[:4] == b"\x7fELF" and raw[5] == 1, "original little-endian ELF")
        machine = struct.unpack_from("<H", raw, 18)[0]
        need(machine == (164 if name == "libggml-htp-v79.so" else 183)
             and (name == "libggml-htp-v79.so" or raw[4] == 2), "original native architecture")
        native_payloads[path] = raw
        native_rows.append({"name":name,"apk_path":path,"bytes":len(raw),"sha256":sha(raw),
                            "source":"byte-identical signed54 APK payload","compiled_here":False})
need(native_payloads["lib/arm64-v8a/libhepta_local_runner.so"] == members["out/libhepta_local_runner.so"],
     "signed54 worker equals original compiled worker")
expected_compiler = data["expected_compiler_inputs"]
need(len(expected_compiler) == CONFIG["compiler_input_count"]
     and len({r["path"] for r in expected_compiler}) == CONFIG["compiler_input_count"], "expected current compiler map")
native_input_rows = []
for row in base_compiler_inputs:
    name = row["path"]
    need(name in target, "original compiler member retained")
    if name != "AndroidManifest.xml" and not (name.startswith("src/") and name.endswith(".java")):
        need(target[name] == before[name] and sha(target[name]) == row["sha256"],
             "all original non-Java compiler/generator/header/flag inputs remain unchanged")
        native_input_rows.append(row)
need({r["path"] for r in expected_compiler}-{r["path"] for r in base_compiler_inputs}
     == set(aggregate["new_paths"]), "only reviewed new pure Java compiler sources")
manifest = ET.fromstring(target["AndroidManifest.xml"])
android = "{http://schemas.android.com/apk/res/android}"
need(manifest.get("package") == "org.trillionnium.hepta.local"
     and manifest.get(android+"versionCode") == str(CONFIG["version_code"])
     and manifest.get(android+"versionName") == CONFIG["version_name"],
     "explicit current main58 source identity")
need([(n.tag,dict(n.attrib)) for n in manifest if n.tag.startswith("uses-permission")]
     == [("uses-permission",{android+"name":"org.trillionnium.hepta.webhelper.permission.BIND_EVIDENCE"})],
     "offline main exact helper binding permission")
need(manifest.find("application").get(android+"extractNativeLibs") == "true",
     "unchanged extracted native libraries; no stored-native alignment claim")
identity_root = Path(CONFIG["identity_root"])
identity_raw = load_bound(identity_root/"RESULT.json", CONFIG["identity_result"], original_facts)
identity_result = strict(identity_raw)
need(identity_result["schema"] == "hepta.main55-installed-apk-identity-host-stage.v1"
     and identity_result["all_pass"] is True and type(identity_result["exit_code"]) is int
     and identity_result["exit_code"] == 0 and identity_result["originals_unchanged"] is True
     and identity_result["source_sha256"] == CONFIG["identity_source"]["sha256"]
     and identity_result["cases"]["cases"] == 10 and identity_result["cases"]["assertions"] == 218
     and identity_result["android_syscalls_doubled"] is True
     and identity_result["actual_android_file_access_executed"] is False
     and identity_result["package_manager_or_certificate_executed"] is False
     and type(identity_result["phone_actions"]) is int and identity_result["phone_actions"] == 0,
     "actual focused identity10 proof with original host-only boundary")
for name,pin in (("SOURCE.py",CONFIG["identity_stage"]),("INPUT.json",CONFIG["identity_input"]),
                 ("WebHelperIdentity.java",CONFIG["identity_source"]),
                 ("InstalledApkIdentityHostTest.java",CONFIG["identity_generated"])):
    original = load_bound(identity_root/name,pin,original_facts)
    if name == "WebHelperIdentity.java":
        need(original == target["src/org/trillionnium/hepta/local/WebHelperIdentity.java"],
             "identity gate compiled the current production projection")
cases_raw = load_bound(identity_root/"CASES.json",
                      {"bytes":identity_result["cases_bytes"],"sha256":identity_result["cases_sha256"]},original_facts)
need(strict(cases_raw) == identity_result["cases"], "actual complete identity cases")
need([s["name"] for s in identity_result["steps"]] == ["javac","identity-cases"]
     and all(type(s["exit_code"]) is int and s["exit_code"] == 0 and s["forced"] is False
             and s["exception"] is None for s in identity_result["steps"]), "identity commands exited normally")
for step in identity_result["steps"]:
    for stream in ("stdout","stderr"):
        row = step[stream]
        need(Path(row["path"]) == identity_root/(step["name"]+"."+stream), "identity fixed log path")
        load_bound(row["path"],row,original_facts)

focused_raw = load_bound(FOCUSED/"RESULT.json", CONFIG["focused_result"], original_facts)
focused_input_raw = load_bound(FOCUSED/"INPUT.json", CONFIG["focused_input"], original_facts)
focused_stage_raw = load_bound(FOCUSED/"stage.py", CONFIG["focused_stage"], original_facts)
focused, focused_input = strict(focused_raw), strict(focused_input_raw)
need(focused["schema"] == "hepta.main58-wire4-focused-host-stage.v1"
     and focused["all_pass"] is True and focused["java_sources"] == 51
     and focused["pure_production_sources"] == 44 and focused["exact_method_projection_count"] == 15
     and focused["current_source_tree_unchanged"] is True
     and focused["prior_successful_run_preserved"] is True
     and focused["prior_successful56_artifacts_preserved"] is True
     and focused["prior_successful57_artifacts_preserved"] is True
     and focused["actual57_projected_methods_changed_here"] == 0
     and focused["actual57_compile_files_changed_here"] is False
     and focused["source_checkpoint_git"] == CONFIG["aggregate"]["git"]
     and focused["current_source_inventory_sha256"] == CONFIG["source_inventory_sha256"]
     and focused["originals_and_written_sources_unchanged"] is True
     and focused["android_compiled"] is False and focused["binder_transport_tested"] is False
     and focused["native_accessibility_tested"] is False
     and type(focused["phone_actions"]) is int and focused["phone_actions"] == 0
     and focused["business_verified"] is False, "actual completed focused host proof, no scope promotion")
need([s["name"] for s in focused["steps"]] == ["compile", "consumer", "arm"]
     and all(type(s["exit_code"]) is int and s["exit_code"] == 0 and s["timed_out"] is False
             and s["forced_kill"] is False and s["exit_observed"] is True for s in focused["steps"]),
     "all three original owned JVM steps completed normally")
for name, count in (("consumer", 20), ("arm", 19)):
    evidence = focused["reports"][name]
    result_raw = load_bound(FOCUSED/(name+"-RESULT.json"), evidence["original"], original_facts)
    actual = strict(result_raw)
    need(actual == evidence["report"] and actual["all_pass"] is True and type(actual["case_count"]) is int
         and actual["case_count"] == count and actual["phone_actions"] == 0 and actual["business_verified"] is False,
         "complete actual focused case original")
for item in focused_input["compile_files"]:
    if item["path"].startswith("src/"):
        need(item["path"] in target and checked(target[item["path"]], item, "focused production source") ==
             load_bound(FOCUSED/"source"/item["path"], item, original_facts), "current production matches actual focused compilation")
for item in focused_input["projection_originals"]:
    name = "src/org/trillionnium/hepta/local/"+item["name"]
    need(checked(target[name], item, "current exact Android projection source") ==
         load_bound(FOCUSED/"projection-originals"/item["name"], item, original_facts),
         "actual focused methods remain current")


calendar_dom_raw = load_bound(CONFIG["calendar_dom"]["path"], CONFIG["calendar_dom"], original_facts)
calendar_ax_raw = load_bound(CONFIG["calendar_ax"]["path"], CONFIG["calendar_ax"], original_facts)
query_runner_raw=checked(target["tests/web-flight/run_query_host_tests.py"],
    CONFIG["query_runner"],"corrected query runner in the complete current source tree")
need(CONFIG["query_runner_integrated_into_source"] is True
     and prior_build["query40"]["runner_corrected_outside_source_tree"] is False
     and prior_build["query40"]["repository_runner_count_guard_known_incompatible"] is False
     and prior_build["query40"]["runner_count_repair_integrated_into_current_source"] is True
     and prior_build["query40"]["runner_sha256"]==sha(query_runner_raw)
     and prior_build["query40"]["historical_prior_external_runner"]["runner_corrected_outside_source_tree"] is True
     and prior_build["query40"]["historical_prior_external_runner"]["repository_runner_count_guard_known_incompatible"] is True
     and prior_build["query40"]["historical_prior_external_runner"]["runner_sha256"]==sha(query_runner_raw),
     "current repository query source equals actual57 integrated runner; actual56 external history remains distinct")
sdk_download_raw = load_bound(Path(CONFIG["sdk_download_root"])/"RESULT.json",
                              CONFIG["sdk_download_result"], original_facts)
sdk_download = strict(sdk_download_raw)
need(sdk_download["schema"] == "hepta.helper6-pocket4-sdk-public-input.v1"
     and sdk_download["revision"] == "official-archive-only-r2"
     and sdk_download["completed"] is True and type(sdk_download["exit_code"]) is int
     and sdk_download["exit_code"] == 0 and sdk_download["originals_unchanged"] is True
     and sdk_download["r8_verified"] is True and sdk_download["sdk_dual_hash_verified"] is True
     and sdk_download["orgjson_ready"] is True and sdk_download["runtime_jars_verified"] is True
     and sdk_download["prior_sdk_failure_flags_preserved"] is True
     and sdk_download["repository_downloaded_here"] is False
     and sdk_download["gitiles_range_retried_here"] is False
     and sdk_download["gitiles_full_body_redownloaded_here"] is False
     and sdk_download["build_executed"] is False and sdk_download["signed"] is False
     and sdk_download["phone_contacted"] is False, "actual dependency-only success with original failures retained")
for role,key in (("r8","r8"),("android_jar","sdk")):
    artifact = sdk_download[key]
    need(artifact["verified"] is True
         and all(artifact[field] == CONFIG["tools"][role][field] for field in ("path","bytes","sha256")),
         "actual SDK/R8 artifact exactly matches this compilation tool pin")
need(sdk_download["sdk"]["official_git_blob"] == "923bafccf73aef996495c559e919ad8be3cabd58"
     and sdk_download["sdk"]["verification_kind"] == "original_sha256_and_official_git_blob",
     "SDK original byte hash and official Git blob both verified")
tools = {}
for name,pin in CONFIG["tools"].items():
    _,facts = read_regular(pin["path"],pin)
    need(name not in ("java","javac","aapt2") or os.access(pin["path"],os.X_OK), "actual host executable")
    tools[name] = facts
    original_facts.append(facts)
started = time.time()
ROOT.mkdir(mode=0o700)  # FIRST MUTATION. Outside handler; a late entry never writes winner evidence.
steps, written, error = [], [], None
result = {"schema":"hepta.main58-pocket4-java-native-reuse-stage.v1","root":str(ROOT),
          "all_pass":False,"exit_code":1,"source_commit":None,"publication_pending":True,
          "source_candidate_git":CONFIG["aggregate"]["git"],"base_source_commit":CONFIG["base_source_commit"],
          "source_file_count":CONFIG["source_file_count"],"compiler_input_count":None,"java_source_count":None,"class_count":None,
          "focused_host_original":CONFIG["focused_result"],"focused_consumer_cases":20,"focused_arm_cases":19,
          "identity_host_original":CONFIG["identity_result"],"identity_cases":10,
          "focused39_rerun":False,"identity10_rerun":False,"original80_43_13_rerun":False,"full101_rerun":False,
          "query40_rerun":False,"android_java_compiled_here":False,"native_recompiled_here":False,
          "native_payloads_verified_from_signed54":True,"native_payloads_reused_from_signed54":False,"external_zipalign_used":False,
          "signed":False,"published":False,"phone_actions":0,"business_verified":False,
          "actual_binder_tested":False,"web_query_executed":False,"web_results_verified":False,
          "shopping_provider_phone_verified":False,"full_static_acceptance_pending":True,
          "helper_required_version_code":6,"helper_protocol":"v4",
          "tools":tools,"steps":steps,"started_epoch":started,
          "original_full_input_reconstructed":False,"original_full_input_reused_from_signed57_build":True,
          "sdk_dependency_result":CONFIG["sdk_download_result"],
          "revision":"sealed-source-successor-from-actual-signed57-r1",
          "prior_successful_build":CONFIG["prior_build_result"],
          "prior_build_root":str(PRIOR_BUILD),"prior_successful_build_preserved":False,
          "predecessor_signed_release":CONFIG["predecessor_release"],
          "predecessor_release_source_commit":CONFIG["predecessor_release_source_commit"],
          "original_source_candidate_git":CONFIG["original_aggregate"]["git"],
          "exact_changed_paths":CONFIG["exact_changed_paths"],
          "compiler_input_changed_paths":compiler_changed_paths,
          "core_materialized_root":str(MATERIALIZED),"same_complete_source_as_core_materialization":True,
          "core101_pass_required_before_this_build":False,
          "post_compile_source_sidecar_required":False,"new_full_input_reconstructed":True}


try:
    written.append(write_new(ROOT/"stage.py",stage_raw))
    written.append(write_new(ROOT/"INPUT.json",input_raw))
    written.append(write_new(ROOT/"PREDECESSOR-SIGNED-RESULT.json",release_raw))
    written.append(write_new(ROOT/"PRIOR-BUILD-RESULT.json",prior_build_raw))
    written.append(write_new(ROOT/"PRIOR-BUILD-FILE-INVENTORY.json",
        encoded([{"path":name,"bytes":item["bytes"],"sha256":item["sha256"]} for name,item in prior_tree_facts.items()])))
    written.append(write_new(ROOT/"SOURCE-DELTAS.json",encoded(CONFIG["source_deltas"])))
    written.append(write_new(ROOT/"SDK-DEPENDENCY-RESULT.json",sdk_download_raw))
    written.append(write_new(ROOT/"AGGREGATE.json",aggregate_raw))
    written.append(write_new(ROOT/"SOURCE-INVENTORY.json",encoded(rows(target))))
    written.append(write_new(ROOT/"BASE-SIGNED-RESULT.json",signed_raw))
    written.append(write_new(ROOT/"BASE-COMPILER-RESULT.json",prior_compiler_raw))
    written.append(write_new(ROOT/"BASE-MAC-STAGE.json",mac_stage_raw))
    written.append(write_new(ROOT/"BASE-NATIVE-COMPILER.stdout",native_build_stdout))
    SOURCE.mkdir(mode=0o700)
    for name,raw in target.items():
        written.append(write_new(SOURCE/name,raw))
    OUT.mkdir(mode=0o700)
    (OUT/"classes").mkdir(mode=0o700)
    (OUT/"dex").mkdir(mode=0o700)
    (ROOT/"tmp").mkdir(mode=0o700)
    compiler_inputs=identity_ns["source_inputs"](SOURCE)
    need(compiler_inputs==expected_compiler,"actual current compiler map equals the complete reviewed successor map")
    java_sources=sorted((SOURCE/"src").rglob("*.java"))
    need(len(java_sources)==CONFIG["java_source_count"]
         and {p.relative_to(SOURCE).as_posix() for p in java_sources}
             == {r["path"] for r in compiler_inputs if r["path"].startswith("src/") and r["path"].endswith(".java")},
         "all sealed current Java inputs included exactly once")
    result["compiler_input_count"]=len(compiler_inputs)
    result["java_source_count"]=len(java_sources)
    result["source_inventory_sha256"]=sha(encoded(rows(target)))
    result["source_inputs"]=compiler_inputs
    written.append(write_new(ROOT/"COMPILER-INPUTS.json",encoded(compiler_inputs)))
    # The original approved runner owns both of its JVM child groups. Its exact
    # Retained case names and reviewed narrow successor additions have exact sealed expectations.
    query=current_query40()
    result["query40"]=query
    result["query40_rerun"]=True
    query_snapshot,query_facts=snapshot(ROOT/"query40")
    written.extend(query_facts.values())
    result["query40_output_inventory_sha256"]=sha(encoded(rows(query_snapshot)))
    written.append(write_new(ROOT/"QUERY40-OUTPUT-INVENTORY.json",encoded(rows(query_snapshot))))
    env=dict(os.environ)
    for name in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):
        env.pop(name,None)
    env.update({"JAVA_HOME":CONFIG["jdk"],"TMPDIR":str(ROOT/"tmp"),"PYTHONDONTWRITEBYTECODE":"1"})
    run_step("javac",[tools["javac"]["path"],"-encoding","UTF-8","--release","8",
                     "-classpath",tools["android_jar"]["path"],"-d",OUT/"classes",*java_sources],180,SOURCE,env)
    class_values,class_facts=snapshot(OUT/"classes")
    need(len(class_values)>0 and all(name.endswith(".class") and raw[:4]==b"\xca\xfe\xba\xbe"
                                    for name,raw in class_values.items()),"actual Java class outputs")
    classes=[OUT/"classes"/name for name in sorted(class_values)]
    result["class_count"]=len(classes)
    written.extend(class_facts.values())
    written.append(write_new(ROOT/"CLASS-INVENTORY.json",encoded(rows(class_values))))
    run_step("d8",[tools["java"]["path"],"-cp",tools["r8"]["path"],"com.android.tools.r8.D8",
                   "--lib",tools["android_jar"]["path"],"--min-api","30","--output",OUT/"dex",*classes],
             180,SOURCE,env)
    need({p.name for p in (OUT/"dex").iterdir()}=={"classes.dex"},"one actual current DEX output")
    dex_raw,dex_facts=read_regular(OUT/"dex/classes.dex")
    need(dex_raw[:4]==b"dex\n" and len(dex_raw)>0,"actual nonempty DEX")
    written.append(dex_facts)
    run_step("aapt2-compile",[tools["aapt2"]["path"],"compile","--dir",SOURCE/"res","-o",OUT/"resources.zip"],
             180,SOURCE,env)
    resources_raw,resources_facts=read_regular(OUT/"resources.zip")
    need(len(resources_raw)>0,"actual compiled resource archive")
    with zipfile.ZipFile(io.BytesIO(resources_raw)) as archive:
        need(archive.testzip() is None and len(archive.infolist())>0
             and len(archive.infolist())==len(set(archive.namelist())),"complete compiled resource archive CRCs")
    written.append(resources_facts)
    run_step("aapt2-link",[tools["aapt2"]["path"],"link","-I",tools["android_jar"]["path"],
             "--manifest",SOURCE/"AndroidManifest.xml","-o",OUT/"base.apk",OUT/"resources.zip"],180,SOURCE,env)
    base_raw,base_facts=read_regular(OUT/"base.apk")
    written.append(base_facts)
    need(identity_ns["source_inputs"](SOURCE)==compiler_inputs,"compiler inputs unchanged during actual Java/DEX/resources")
    # These three retained artifacts are copied from the original pinned compiler
    # archive. Their records explicitly identify them as reused, not rebuilt here.
    reused_worker=write_new(OUT/"libhepta_local_runner.so",members["out/libhepta_local_runner.so"])
    reused_generated=write_new(OUT/"worker-appuid.c",members["out/worker-appuid.c"])
    reused_disassembly=write_new(OUT/"native-sha256-disassembly.txt",members["out/native-sha256-disassembly.txt"])
    written.extend([reused_worker,reused_generated,reused_disassembly])
    native_reuse={
        "schema":"hepta.signed54-native-payload-reuse.v1","native_recompiled_here":False,
        "source_signed_result":CONFIG["base_signed_result"],"source_signed_apk":CONFIG["base_apk"],
        "source_commit":CONFIG["base_source_commit"],"source_archive":CONFIG["base_archive"],
        "original_compiler_receipt":CONFIG["base_compiler"],"original_actual_mac_stage":CONFIG["base_mac_stage"],
        "original_build_stdout":CONFIG["base_build_stdout"],"original_native_compiler_command":native_commands[0],
        "original_native_build_script_unmodified":True,"original_assembly_script_unmodified":True,
        "original_worker_adapter":prior["worker_adapter"],
        "original_sha256_instruction_gate":prior["sha256_instruction_gate"],
        "current_native_generator_header_flag_inputs":native_input_rows,
        "all_original_non_java_except_manifest_compiler_inputs_unchanged":True,
        "current_worker":reused_worker,"retained_generated_source":reused_generated,
        "retained_disassembly":reused_disassembly,"native_payload_count":17,"native_payloads":native_rows,
        "all_payloads_byte_identical_to_signed54":True,"ndk_or_clang_executed_here":False,
        "native_generator_executed_here":False,"new_native_runtime_behavior_claimed":False}
    written.append(write_new(ROOT/"NATIVE-REUSE.json",encoded(native_reuse)))
    receipt={
        "schema":"hepta.pocket4-java-native-reuse-build.v1",
        "compile_sdk":34,"target_sdk":35,"min_sdk":30,"java_target":8,
        "build_host_platform":"linux","source_head_from_ci":None,"source_commit":None,
        "source_candidate_git":CONFIG["aggregate"]["git"],"source_inventory_sha256":CONFIG["source_inventory_sha256"],
        "source_inputs":compiler_inputs,"source_root":str(SOURCE),"java_source_count":len(java_sources),"class_count":len(classes),
        "android_java_compiled_here":True,"dex_compiled_here":True,"resources_compiled_here":True,
        "native_recompiled_here":False,"native_payloads_reused_from_signed54":True,"native_reuse":native_reuse,
        "artifacts":[dex_facts,base_facts,reused_worker],"compiled_resources":resources_facts,
        "tools":tools,"actual_java_dex_resource_steps":steps[:4],
        "version_code":CONFIG["version_code"],"version_name":CONFIG["version_name"],
        "signed":False,"published":False,"phone_actions":0,"business_verified":False}
    receipt_raw=encoded(receipt)
    written.append(write_new(OUT/"pocket4-build-receipt.json",receipt_raw))
    build_asset=identity_ns["actual_build_identity"](SOURCE,receipt)
    asset_object=strict(build_asset)
    need(asset_object["schema"]=="hepta.actual-build-inputs.v1" and asset_object["version_code"]==CONFIG["version_code"]
         and asset_object["source_inputs"]==compiler_inputs,"actual deterministic current build identity")
    written.append(write_new(OUT/"hepta-build-identity.json",build_asset))
    unsigned_facts,resource_layout,payload_rows=build_unsigned(base_raw,dex_raw,build_asset)
    written.append(unsigned_facts)
    unsigned=Path(unsigned_facts["path"])
    for name,argv in (
        ("badging",[tools["aapt2"]["path"],"dump","badging",unsigned]),
        ("permissions",[tools["aapt2"]["path"],"dump","permissions",unsigned]),
        ("manifest",[tools["aapt2"]["path"],"dump","xmltree",unsigned,"--file","AndroidManifest.xml"]),
        ("accessibility",[tools["aapt2"]["path"],"dump","xmltree",unsigned,"--file","res/xml/hepta_accessibility_service.xml"])):
        run_step(name,argv,30,SOURCE,env)
    badging=read_regular(ROOT/"badging.stdout")[0].decode("utf-8","strict")
    permissions=read_regular(ROOT/"permissions.stdout")[0].decode("utf-8","strict")
    manifest_dump=read_regular(ROOT/"manifest.stdout")[0].decode("utf-8","strict")
    accessibility=read_regular(ROOT/"accessibility.stdout")[0].decode("utf-8","strict")
    actual_permissions=[]
    for line in permissions.splitlines():
        if line.strip().startswith("uses-permission"):
            entry=re.fullmatch(r"uses-permission: name='([^']+)'",line.strip())
            need(entry is not None,"exact compiled permission record")
            actual_permissions.append(entry.group(1))
    need(actual_permissions==["org.trillionnium.hepta.webhelper.permission.BIND_EVIDENCE"]
         and "android.permission.INTERNET" not in manifest_dump,"exact offline compiled permission")
    apk_identity=re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'",badging,re.MULTILINE)
    need(apk_identity is not None and apk_identity.groups()==
         ("org.trillionnium.hepta.local",str(CONFIG["version_code"]),CONFIG["version_name"]),"actual unsigned package/version")
    need("native-code: 'arm64-v8a'" in badging,"actual compiled ABI declaration")
    for expected in ("libadsprpc.so","libcdsprpc.so","libOpenCL.so","android.permission.BIND_ACCESSIBILITY_SERVICE",
                     "android.intent.category.LAUNCHER","org.trillionnium.hepta.webhelper"):
        need(expected in manifest_dump,"actual compiled declaration: "+expected)
    for capability in ("canTakeScreenshot","canRetrieveWindowContent","canPerformGestures"):
        need(capability in accessibility,"actual accessibility metadata: "+capability)
    need(manifest.find("application/service").get(android+"permission")=="android.permission.BIND_ACCESSIBILITY_SERVICE"
         and not manifest.findall("application/provider") and not manifest.findall("application/receiver"),
         "source accessibility guard and no external providers/receivers")
    for step in steps:
        written.extend([step["stdout"],step["stderr"]])
    written.append(write_new(ROOT/"UNSIGNED-PAYLOADS.json",encoded(payload_rows)))
    result.update({
        "android_java_compiled_here":True,"dex_compiled_here":True,"resources_compiled_here":True,
        "native_payloads_reused_from_signed54":True,"native_reuse":native_reuse,
        "compiler_receipt":{"path":str(OUT/"pocket4-build-receipt.json"),"bytes":len(receipt_raw),"sha256":sha(receipt_raw)},
        "unsigned_apk":unsigned_facts,"unsigned_apk_payload_count":len(payload_rows),
        "resources_layout":resource_layout,"actual_permissions":actual_permissions,
        "build_identity":{"bytes":len(build_asset),"sha256":sha(build_asset),"version_code":CONFIG["version_code"],
                          "compiler_input_count":len(compiler_inputs)},
        "all_pass":True,"exit_code":0})
except BaseException as failure:
    error=type(failure).__name__+": "+str(failure)
    result["all_pass"]=False
    result["exit_code"]=1
    result["error"]=error
    try:
        write_new(ROOT/"ERROR.txt",traceback.format_exc().encode("utf-8"))
    except Exception as logging_failure:
        result["error_record_failure"]=type(logging_failure).__name__+": "+str(logging_failure)
finally:
    integrity_error=None
    try:
        for facts in original_facts:
            unchanged(facts)
        for facts in written:
            unchanged(facts)
        base_after,base_after_facts=snapshot(BASE/"source")
        need(base_after==before and base_after_facts==before_facts,"signed54 source bytes and identities unchanged")
        if SOURCE.exists():
            source_after,_=snapshot(SOURCE)
            need(source_after==target,"new current source has the exact complete successor member map")
            need(identity_ns["source_inputs"](SOURCE)==expected_compiler,"new compiler map unchanged")
        need(prior_artifact_paths(PRIOR_BUILD) == list(prior_tree_facts), "original signed57 Android file membership unchanged")
        prior_source_after, prior_source_after_facts = snapshot(PRIOR_BUILD/"source")
        need(prior_source_after == prior_source and prior_source_after_facts == prior_source_facts,
             "original signed57 Android source bytes and identities unchanged")
        materialized_after, materialized_after_facts = snapshot(MATERIALIZED/"source")
        need(materialized_after == target and materialized_after_facts == materialized_source_facts,
             "successor core materialized source bytes and identities unchanged")
        result["prior_successful_build_preserved"]=True
        result["materialized_source_unchanged"]=True
        result["originals_unchanged"]=True
        result["written_files_unchanged"]=True
        result["current_source_unchanged"]=SOURCE.exists()
    except BaseException as failure:
        integrity_error=type(failure).__name__+": "+str(failure)
        result["integrity_error"]=integrity_error
        result["originals_unchanged"]=False
        result["all_pass"]=False
        result["exit_code"]=1
    result["finished_epoch"]=time.time()
    result["elapsed_seconds"]=result["finished_epoch"]-started
    result["stage_sha256"]=sha(stage_raw)
    result["input_sha256"]=sha(input_raw)
    result["original_guard_count"]=len(original_facts)
    result["written_guard_count"]=len(written)
    result["native_recompiled_here"]=False
    result["ndk_or_clang_executed_here"]=False
    result["all_pass"]=bool(result["all_pass"] and error is None and integrity_error is None)
    result_raw=encoded(result)
    result_facts=write_new(ROOT/"RESULT.json",result_raw)
    summary={"schema":"hepta.main58-pocket4-java-native-reuse-summary.v1","root":str(ROOT),
             "all_pass":result["all_pass"],"exit_code":result["exit_code"],"error":result.get("error"),
             "integrity_error":result.get("integrity_error"),"result":result_facts,
             "source_file_count":CONFIG["source_file_count"],"source_inventory_sha256":CONFIG["source_inventory_sha256"],
             "compiler_input_count":result.get("compiler_input_count"),"java_source_count":result.get("java_source_count"),
             "class_count":result.get("class_count"),"actual_tool_step_count":len(steps),
             "revision":result["revision"],"prior_successful_build_preserved":result["prior_successful_build_preserved"],
             "source_candidate_git":CONFIG["aggregate"]["git"],
             "same_complete_source_as_core_materialization":True,"post_compile_source_sidecar_required":False,
             "actual_query40_passed":result.get("query40",{}).get("report",{}).get("all_pass") is True,
             "focused39_rerun":False,"identity10_rerun":False,"native_recompiled_here":False,
             "native_payloads_reused_from_signed54":result["native_payloads_reused_from_signed54"],
             "unsigned_apk":result.get("unsigned_apk"),"signed":False,"published":False,
             "phone_actions":0,"business_verified":False,"full_static_acceptance_pending":True}
    write_new(ROOT/"SUMMARY.json",encoded(summary))
    print(json.dumps(summary,ensure_ascii=False,sort_keys=True,allow_nan=False),flush=True)
raise SystemExit(0 if result["all_pass"] else 1)
