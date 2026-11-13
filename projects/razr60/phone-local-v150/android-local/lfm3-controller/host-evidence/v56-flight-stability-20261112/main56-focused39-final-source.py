#!/usr/bin/env python3
"""Recompile the original20+19 focused cases against the exact Main56 source.
All15 production blocks are copied from actual current source; only3 changed.
Dormant Flight interfaces throw; real44 pure classes compile independently.
No phone, Android build, Binder, native UI or business-success claim is made.
"""
import gzip, hashlib, json, os, signal, stat, subprocess, sys, time, traceback
from pathlib import Path
CONFIG = json.loads("{\"root\":\"/home/alex/hepta-local-007f-20261111/v56-main-wire4-host-p4-r1\",\"input_path\":\"/home/alex/hepta-local-007f-20261111/v55-main-wire4-host-p4-r1.input.json.gz\",\"input_bytes\":190790,\"input_sha256\":\"c00a122765e8680298ea9066c246497cd94ad7b88605cd035ae20f4d7366bbe6\",\"decoded_bytes\":932162,\"decoded_sha256\":\"74e902506929b5871518ff33a5e3cf9409bfb96985097cfbbdbca5b592f880e0\",\"java\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/java\",\"bytes\":14544,\"sha256\":\"bb70208200cb6538b877d80478141194a716edb591f4910ec106589291e99196\"},\"javac\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/javac\",\"bytes\":14592,\"sha256\":\"2aaf03d13aeb80b8269696f2dcd9f4937d7366bbc68f91fdc703cf157e8f39c4\"},\"json\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-public-inputs-r1/host-json/json-20240303.jar\",\"bytes\":78332,\"sha256\":\"3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed\"},\"expected_paths\":[\"src/org/trillionnium/hepta/background/FixedIntentTarget.java\",\"src/org/trillionnium/hepta/background/FixedIntentTools.java\",\"src/org/trillionnium/hepta/local/ActionDecision.java\",\"src/org/trillionnium/hepta/local/AppCatalogueRanker.java\",\"src/org/trillionnium/hepta/local/CsairCalendar.java\",\"src/org/trillionnium/hepta/local/CsairCityPicker.java\",\"src/org/trillionnium/hepta/local/CsairFlightForm.java\",\"src/org/trillionnium/hepta/local/DecisionGrammar.java\",\"src/org/trillionnium/hepta/local/ImeVisibility.java\",\"src/org/trillionnium/hepta/local/MiPublicProductPage.java\",\"src/org/trillionnium/hepta/local/NotesCompletionEvidence.java\",\"src/org/trillionnium/hepta/local/NotesCreateWorkflow.java\",\"src/org/trillionnium/hepta/local/NotesOwnerIntent.java\",\"src/org/trillionnium/hepta/local/ObservationState.java\",\"src/org/trillionnium/hepta/local/ObservedAppLabels.java\",\"src/org/trillionnium/hepta/local/ObservedChildText.java\",\"src/org/trillionnium/hepta/local/ObservedImeEnter.java\",\"src/org/trillionnium/hepta/local/ObservedScrollActions.java\",\"src/org/trillionnium/hepta/local/ObservedTargetLabels.java\",\"src/org/trillionnium/hepta/local/ObservedWindowMetadata.java\",\"src/org/trillionnium/hepta/local/PhoneObservation.java\",\"src/org/trillionnium/hepta/local/TaskAuthorization.java\",\"src/org/trillionnium/hepta/local/TaskCompletionGate.java\",\"src/org/trillionnium/hepta/local/WebEvidenceJson.java\",\"src/org/trillionnium/hepta/local/WebEvidenceReceipt.java\",\"src/org/trillionnium/hepta/local/WebFlightDomain.java\",\"src/org/trillionnium/hepta/local/WebFlightNativeStability.java\",\"src/org/trillionnium/hepta/local/WebFlightProgress.java\",\"src/org/trillionnium/hepta/local/WebNativeGeometry.java\",\"src/org/trillionnium/hepta/local/WebRegionNativeBridge.java\",\"src/org/trillionnium/hepta/local/WebShoppingDomain.java\",\"src/org/trillionnium/hepta/local/WebTaskDomain.java\",\"src/org/trillionnium/hepta/local/web/WebFlightGoal.java\",\"src/org/trillionnium/hepta/local/web/WebShoppingGoal.java\",\"src/org/trillionnium/hepta/webprotocol/WebDomCanonical.java\",\"src/org/trillionnium/hepta/webprotocol/WebDomStability.java\",\"src/org/trillionnium/hepta/webprotocol/WebEvidenceBinding.java\",\"src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java\",\"src/org/trillionnium/hepta/webprotocol/WebMiActionRegion.java\",\"src/org/trillionnium/hepta/webprotocol/WebObservedNavigation.java\",\"src/org/trillionnium/hepta/webprotocol/WebRecoveryPolicy.java\",\"src/org/trillionnium/hepta/webprotocol/WebSitePolicy.java\",\"src/org/trillionnium/hepta/webprotocol/WebStorageEvidence.java\",\"src/org/trillionnium/hepta/webprotocol/WebTaskPurpose.java\",\"tests/main55-wire4/WebArmDispatchHostTest.java\",\"tests/main55-wire4/WebEvidenceClientArmProjection.java\",\"tests/main55-wire4/WebFlightSessionArmProjection.java\",\"tests/main55-wire4/WebWire4ConsumerHostTest.java\",\"tests/main55-wire4/WebWire4SyntheticFactory.java\",\"tests/main55-wire4/android/graphics/Rect.java\",\"tests/main55-wire4/android/os/SystemClock.java\"],\"input_scope_root\":\"/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v55-main-wire4-host-r1\",\"orgjson_ready\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-public-inputs-r1/ORGJSON-READY.json\",\"bytes\":1289,\"sha256\":\"37f3b1790fce237f6339cab159015da7937e6517cc4a97f4dc16443c74e01d7b\"},\"derived_bytes\":933229,\"derived_sha256\":\"846beb1494f4a16d55949dff3e3840250a4f864d0c7260aabf415a1db2f098c4\",\"fixture_type_adapter\":{\"schema\":\"hepta.explicit-synthetic-map-json-adapter.v1\",\"path\":\"tests/main55-wire4/WebWire4SyntheticFactory.java\",\"before\":\"WebEvidenceBinding.canonical(TaskAuthorization.parse(owner).evidence())\",\"after\":\"WebEvidenceBinding.canonical(new JSONObject(TaskAuthorization.parse(owner).evidence()))\",\"count\":1,\"original_factory\":{\"bytes\":13173,\"sha256\":\"581fcf026f8c374f311d628a37f2e40584d92cedbd2a383e355b755655431330\"},\"compiled_factory\":{\"bytes\":13189,\"sha256\":\"ed0ea43b11b828248afa432fbfd9ed4137302ed756b11104dc4d26be15c34d7d\"},\"original_methods_sha256\":\"75778aa5cec56163cae8563e184e930c73160d17a6b0cb61b702fbe33c038915\",\"compiled_methods_sha256\":\"15df93ebd23df44a7ed66440dc2bccdb996040bde93cbc406d09aa611d2c9840\",\"production_sources_changed\":false,\"assertions_changed\":false},\"prior_failure\":{\"root\":\"/home/alex/hepta-local-007f-20261111/v55-main-wire4-host-p4-r1\",\"path\":\"/home/alex/hepta-local-007f-20261111/v55-main-wire4-host-p4-r1/RESULT.json\",\"bytes\":23810,\"sha256\":\"94f173f6a003bf934ebedcb03d898b0ac1edcf5fe95f15a813484c68a46ff600\"},\"provider_type_adapter\":{\"schema\":\"hepta.explicit-host-provider-map-api-adapter.v1\",\"path\":\"tests/main55-wire4/WebFlightSessionArmProjection.java\",\"replacements\":[{\"before\":\"JSONObject evidence(WebFlightDomain source){throw new AssertionError(\\\"no flight\\\");}\",\"after\":\"java.util.Map<String,Object> evidence(WebFlightDomain source){throw new AssertionError(\\\"no flight\\\");}\",\"count\":1},{\"before\":\"JSONObject evidence()throws Exception{return new JSONObject().put(\\\"host_provider_double\\\",true).put(\\\"dom_sha256\\\",domSha).put(\\\"business_verified\\\",false);}\",\"after\":\"java.util.Map<String,Object> evidence(){\\n            java.util.Map<String,Object> out=new java.util.LinkedHashMap<String,Object>();\\n            out.put(\\\"host_provider_double\\\",true);out.put(\\\"dom_sha256\\\",domSha);out.put(\\\"business_verified\\\",false);return out;\\n        }\",\"count\":1}],\"original\":{\"bytes\":25296,\"sha256\":\"64d071d1486cfe61a35001e963e9dad82db650191a2de4a67b9354ebbfb3aa74\"},\"compiled\":{\"bytes\":25428,\"sha256\":\"b9f0cd4529d269d6b989178bafe4f622e7441f70c493874fa6bee0095d1769be\"},\"actual_api_sources\":[{\"path\":\"src/org/trillionnium/hepta/local/WebTaskDomain.java\",\"bytes\":8817,\"sha256\":\"fe2eb43d1546ae56803133b86fc959f3a5b5e036821553dddfc93fe02bdc9b98\",\"git\":\"c64cbf8cbcfbcb9c5734049613d575f45380cb09\",\"signature\":\"Map<String,Object> evidence()\"},{\"path\":\"src/org/trillionnium/hepta/local/WebFlightProgress.java\",\"bytes\":16832,\"sha256\":\"47630c3e36b56470ebdb8353b24c68f94bf6274d7fefc08133cd7a78946a0691\",\"git\":\"08e5a189ee8b2f16980f7f1e9dc08ae8454ef02d\",\"signature\":\"Map<String,Object> evidence(WebFlightDomain now)\"}],\"original_three_provider_values_unchanged\":true,\"dormant_flight_body_still_throws\":true,\"record_false_assertion_unchanged\":true,\"all_fifteen_production_method_blocks_unchanged\":true,\"production_sources_changed\":false,\"test_assertions_changed\":false},\"provider_adapted_bytes\":935559,\"provider_adapted_sha256\":\"f9577768563f5fbf88bf77b0d484038c7ccd87b07d0ae5a79fb55ef92c987d4e\",\"second_prior_failure\":{\"root\":\"/home/alex/hepta-local-007f-20261111/v55-main-wire4-host-p4-r2\",\"path\":\"/home/alex/hepta-local-007f-20261111/v55-main-wire4-host-p4-r2/RESULT.json\",\"bytes\":29674,\"sha256\":\"ab4cf9b52cfb10b7cab5ec2286861358727d89fc23a54147c628570467030670\"},\"current\":{\"source_root\":\"/home/alex/hepta-local-007f-20261111/v56-main-core101-materialized-host-r2/source\",\"materialized_root\":\"/home/alex/hepta-local-007f-20261111/v56-main-core101-materialized-host-r2\",\"aggregate\":{\"bytes\":1427055,\"sha256\":\"c1cc7cc16eef4c3a34131ee719101a69db080b76e72c98f03248036fc6fd628f\",\"git_blob_sha\":\"0803dec4b6acc359b810bb79ca6fdd01ada69a8c\"},\"inventory\":{\"bytes\":103795,\"sha256\":\"ca24673843908c7f9343c949af64b8393e69ce53605128782036ae9ce9d1f46e\"},\"derived\":{\"bytes\":1283344,\"sha256\":\"25b80314fb000cf4e48a56ad4e198d6b2fb0917802e1f687c5d041f17e04a13b\",\"git_blob_sha\":\"baf4bf959ce91b7510694cf393866f056a65cf51\"},\"prior_root\":\"/home/alex/hepta-local-007f-20261111/v55-main-wire4-host-p4-r3\",\"prior_result\":{\"bytes\":33544,\"sha256\":\"cbe61abb7310ae18f58898a17a7a146f5754a573158dec807c90f74f6d9d7df5\",\"git_blob_sha\":\"ec18ea8db941429ca4a697a72c3b023b83644a89\"},\"prior_input\":{\"bytes\":935559,\"sha256\":\"f9577768563f5fbf88bf77b0d484038c7ccd87b07d0ae5a79fb55ef92c987d4e\",\"git_blob_sha\":\"d3390ca0395e8f925f7c3b93cf502f967ab6a72f\"},\"key\":\"007f-v56-main-wire4-host-p4-r1-current-session\"}}")
CURRENT_DELTA = json.loads("{\"schema\":\"hepta.main56-wire4-exact-input-derivation.v1\",\"base\":{\"bytes\":935559,\"sha256\":\"f9577768563f5fbf88bf77b0d484038c7ccd87b07d0ae5a79fb55ef92c987d4e\",\"git_blob_sha\":\"d3390ca0395e8f925f7c3b93cf502f967ab6a72f\"},\"result\":{\"bytes\":1283344,\"sha256\":\"25b80314fb000cf4e48a56ad4e198d6b2fb0917802e1f687c5d041f17e04a13b\",\"git_blob_sha\":\"baf4bf959ce91b7510694cf393866f056a65cf51\"},\"aggregate\":{\"bytes\":1427055,\"sha256\":\"c1cc7cc16eef4c3a34131ee719101a69db080b76e72c98f03248036fc6fd628f\",\"git_blob_sha\":\"0803dec4b6acc359b810bb79ca6fdd01ada69a8c\"},\"pure_compilation_inputs\":[{\"path\":\"src/org/trillionnium/hepta/background/FixedIntentTarget.java\",\"bytes\":2730,\"sha256\":\"f5f3936a8185185cf5f036a74665ee6edfbd5c1f617299dd9cd6edd4bf7b23e2\",\"git_blob_sha\":\"0a34b57522ec86255612bb35208c2678639e1aa3\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/background/FixedIntentTools.java\",\"bytes\":4137,\"sha256\":\"c20285039abaf4ad6028ffb18c1b5e755eccb9a13059576817e557177a294947\",\"git_blob_sha\":\"f472bf388c0c219458298376679db03f50010528\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/ActionDecision.java\",\"bytes\":25712,\"sha256\":\"ee2a0481bb1ad0d2a3dd95b501c101d1955f4f1142adfe150ba3f9643fa88b20\",\"git_blob_sha\":\"91dd78c86d2461b2d0751be87c2f68aef32c02a7\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/AppCatalogueRanker.java\",\"bytes\":9217,\"sha256\":\"0bc99b3864ea994ee53ef9c0d5f256ae66309ed19c9104f892c2dbf840597075\",\"git_blob_sha\":\"6224f5c241d3aa75c2b37e2daa7cf3744b1f6bea\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/CsairCityPicker.java\",\"bytes\":10363,\"sha256\":\"699f1eebe2db1ae4d7973f95f51c342748c24d767efd6f1a998d27f60c9b339f\",\"git_blob_sha\":\"9f70cfcbe936d659882e5a5ee029324ac17b343c\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/CsairFlightForm.java\",\"bytes\":15870,\"sha256\":\"27c88417bbfffc9b67d7a0a4cef896c1499b56fadb326e4985c84f5dd2cb0ef8\",\"git_blob_sha\":\"349052c61a86d89d208dc7897a72285035c67e97\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/DecisionGrammar.java\",\"bytes\":30605,\"sha256\":\"236d22187abfe777705d337241e310dd617b1c4c21ae39df4f52d960a1e106ca\",\"git_blob_sha\":\"b2b1aba87d179ed9054baa25227380825510baf0\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/ImeVisibility.java\",\"bytes\":711,\"sha256\":\"4e7fdaf10d6d502e77642fb043296e8da5d94fbfc78d884826f60dafed8f6e36\",\"git_blob_sha\":\"eafd2a2872fe9c4928a23c8e91f4d622384480ef\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/MiPublicProductPage.java\",\"bytes\":17440,\"sha256\":\"aaddee9837555083ec1d796b67a2cfc37a280b023b12b2dbd4e474d47586ac8b\",\"git_blob_sha\":\"4d38f27e602302f71ecbf1c4e2e4fcb367fa9fe0\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/NotesCompletionEvidence.java\",\"bytes\":18644,\"sha256\":\"1ce2e8dfc588ae51545f88a0eccb2002cfd91f647db0225fd95398ff04157f7d\",\"git_blob_sha\":\"5da9ae144dca74f67916729ec5b7d2b6ae0dbc00\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/NotesCreateWorkflow.java\",\"bytes\":21099,\"sha256\":\"0995cd9a7f5897d2dab5827a432eaa13cc7d8d6363ffda415baa6d566d80d80d\",\"git_blob_sha\":\"e39942a3897444cdeb57b5642c3ea8c58213f362\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/NotesOwnerIntent.java\",\"bytes\":12329,\"sha256\":\"c3d8406e7d3bc6e513e0bad47d043f7d981cca82f5bbac095dce70aa84700e3f\",\"git_blob_sha\":\"1caf398a16da3c2544a9a93db7707e68f08d269f\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/ObservationState.java\",\"bytes\":1258,\"sha256\":\"a2a664a3567995de8665e66d7667cfc089277fdd16175aa9dab837f7919dd257\",\"git_blob_sha\":\"6324f42b92d0b9a4292d4e0500a5a42e49a80c98\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/ObservedAppLabels.java\",\"bytes\":4889,\"sha256\":\"0276171bb8aaebee880a6d36fea5cbfdb157b09d2728a07148e4ce85d5ffbb9e\",\"git_blob_sha\":\"e3fc67e664176d560735cf2bc39199b2e0ab35c9\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/ObservedChildText.java\",\"bytes\":10858,\"sha256\":\"56433b62f9c4c895edac441160fcdc4aaee7365586daa4b86863448dc4dd54d5\",\"git_blob_sha\":\"9a5132adbff599b4185eef6d7ee424a3bd20c060\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/ObservedImeEnter.java\",\"bytes\":4665,\"sha256\":\"e449d61e928dca5a72730b5394fa8f95a7db4dd4006440a95f839818e165acf1\",\"git_blob_sha\":\"ee045dd05a5e3c66844f2d2a19a65836d9949c7f\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/ObservedScrollActions.java\",\"bytes\":2303,\"sha256\":\"c31012cf776fbc4177d6c617341d006f4a45ed63df3cfc435f705e515ebbc188\",\"git_blob_sha\":\"28b58204a76d6e1072705fdd23391b82d9d4d6e2\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/ObservedTargetLabels.java\",\"bytes\":4685,\"sha256\":\"c4e1b1a7ae0223fc7cda90864c6a5c3759a2875bb435359464672bc79465c8ba\",\"git_blob_sha\":\"7046527d72f32ded9cf4bd702f30538145be9d29\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/ObservedWindowMetadata.java\",\"bytes\":4536,\"sha256\":\"73948e97e6a164ef27753ba0536d0cfadac2ee670179aa2e5b4bb2af0e9e66c5\",\"git_blob_sha\":\"b6a949ed9b154778e3b5634404362b27617e6621\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/PhoneObservation.java\",\"bytes\":24711,\"sha256\":\"9dc1033ffc989b2a957e0999bb40d5c48d97117d89150a173141ae7cc7eff8d0\",\"git_blob_sha\":\"1655e8d918e689368938560475c0c62ca94bd04d\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/TaskAuthorization.java\",\"bytes\":23598,\"sha256\":\"9dbcabb1d4f505d581c2dc4b9fd772a4f7578344573c372e1831c84e2f82ecc8\",\"git_blob_sha\":\"346e1790710fa4f0d62a59053328733773c9fe61\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/TaskCompletionGate.java\",\"bytes\":49971,\"sha256\":\"ad417d98fbd7b12bf4373270a1206c11984682c9f35b7b4a5179bb9fbff7ba98\",\"git_blob_sha\":\"48323262aaf10962f0a481cafc18c56bc82e936b\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/WebEvidenceJson.java\",\"bytes\":7253,\"sha256\":\"4f9c66cc527948d498f941543240d2bb304610b388735f3bc7264b9ccefa4e1e\",\"git_blob_sha\":\"be6a9acae9684c474d61fb0d991065793cccbd99\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/WebEvidenceReceipt.java\",\"bytes\":29292,\"sha256\":\"85bd14c7dc45aee8fbc1c290299cd2b123c848f9d5c08634b4b2b66daeeb5cda\",\"git_blob_sha\":\"ba05c6869d365f2c3a2d1d8b3036614d3a92f121\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/WebFlightDomain.java\",\"bytes\":43483,\"sha256\":\"a1be374d093186d8ae58c77aaa2a65e289ff3a9d89c31bae7eef9f223672c6a5\",\"git_blob_sha\":\"da12c492e77b165efa68fce434f778ca2ca22361\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/WebNativeGeometry.java\",\"bytes\":14220,\"sha256\":\"a61e9601699fd7480c4f09be2c29de9cf755903a222c79efbfc9efbd23afbc49\",\"git_blob_sha\":\"65207b0ba2e4f77a7e21f7ae9f24df5315956ec3\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/WebShoppingDomain.java\",\"bytes\":31717,\"sha256\":\"bbf256e37eb5cc3a1619371e9c29dc5f7af3139eeb4f602f602cf0f05551bf92\",\"git_blob_sha\":\"78c1c4d616a815dbf31b214f0fb74754745c967c\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/WebTaskDomain.java\",\"bytes\":8817,\"sha256\":\"fe2eb43d1546ae56803133b86fc959f3a5b5e036821553dddfc93fe02bdc9b98\",\"git_blob_sha\":\"c64cbf8cbcfbcb9c5734049613d575f45380cb09\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/web/WebFlightGoal.java\",\"bytes\":9611,\"sha256\":\"02f260915f2b64894b8cd1ed4223392ace9964920d9b77e6765548252d9624ac\",\"git_blob_sha\":\"e2c2e21136231dd4321d3de29f8ca41a813d7bd5\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/web/WebShoppingGoal.java\",\"bytes\":10767,\"sha256\":\"b8eb72eddb99842758dc39b347d2679d247714b97e0a0afe6df217bf2e8cd8c8\",\"git_blob_sha\":\"2cfd308f8e4f68549e177a2cc490b08379b978d0\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/webprotocol/WebEvidenceBinding.java\",\"bytes\":4089,\"sha256\":\"90a414863297c1ff173fd14a7b31dce62bb5fbb561e7625f1fe3eb0dace47af7\",\"git_blob_sha\":\"6d53345301dfa06ed46eabaf2d82419640eb6ce8\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java\",\"bytes\":5933,\"sha256\":\"3966bbe1122f6a6e13bf211291332aa63f755a891800d04169016958946f8f0e\",\"git_blob_sha\":\"e333c14a306bfc8a5fb79b636fc9da16d45ae73f\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/webprotocol/WebRecoveryPolicy.java\",\"bytes\":36054,\"sha256\":\"e5bba55512b5b71f084282170d2708461d8b62f536f03ba4f3b074a4a0502ce0\",\"git_blob_sha\":\"4daa7335854e14df6de32b36e608f53a28a2a095\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/webprotocol/WebSitePolicy.java\",\"bytes\":5255,\"sha256\":\"d74bf8292782fc7a9e48f3460b8961eecd009d038c8b4e94431b94ecdd04043a\",\"git_blob_sha\":\"e142eb0d3a8af4e24becf29256e7ca2536c192b3\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/webprotocol/WebStorageEvidence.java\",\"bytes\":8539,\"sha256\":\"9e8df742ad0fdaac0fbc051c99772a52fbb40aae49f0a43589e252e71acc7fc0\",\"git_blob_sha\":\"1560094f8a3d3ffcc727d3066f298576be3d709c\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/webprotocol/WebTaskPurpose.java\",\"bytes\":6731,\"sha256\":\"92303867e09343ebcbb3620b9a5850bce683c1d94988d1e534dd272dcaea8647\",\"git_blob_sha\":\"15f4d0cb484af754a00ed10580cd95d56455f434\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/CsairCalendar.java\",\"bytes\":20890,\"sha256\":\"9bc3019994e12493a6c2c6882a983c0021cb875ad6159033777c2c2c73618434\",\"git_blob_sha\":\"d763010ffe1281775ba772e9498b974b7af14be1\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/WebFlightProgress.java\",\"bytes\":16832,\"sha256\":\"47630c3e36b56470ebdb8353b24c68f94bf6274d7fefc08133cd7a78946a0691\",\"git_blob_sha\":\"08e5a189ee8b2f16980f7f1e9dc08ae8454ef02d\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/webprotocol/WebDomCanonical.java\",\"bytes\":4424,\"sha256\":\"55209ef608fad0d8794d439aab2baf69bd7c8b043289c80ca7b25acaad1ff3d7\",\"git_blob_sha\":\"4e2fc663c9a772eedc4d38852a8f6c2c284f179c\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/webprotocol/WebDomStability.java\",\"bytes\":16055,\"sha256\":\"f7e432c1191008afa25a134147cd6fd133f975e102aa4cab722da3dc82a4ea53\",\"git_blob_sha\":\"1865fcd42f7655613991fee167f252c1887ce5e1\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/webprotocol/WebMiActionRegion.java\",\"bytes\":20795,\"sha256\":\"027de25550bac1e58d835c1a0582f5f14aff144b76a2f4889f9d48b4f1abcd04\",\"git_blob_sha\":\"1872c6ca836ad9371f4473ec97cd92136f9af552\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/webprotocol/WebObservedNavigation.java\",\"bytes\":23060,\"sha256\":\"e524d91f50ec8d911692e371fed000d65e1be2f703f3efe36497ae64fd358132\",\"git_blob_sha\":\"fd79658b986c0a9e37b2db26d156341719b44d15\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/WebRegionNativeBridge.java\",\"bytes\":17427,\"sha256\":\"faf50cafc7b11e763a840def5bee6c2cff77535c4a904c06ccd7d74afa489ca2\",\"git_blob_sha\":\"f995c83a65a64013b2eb5907ca6a9b78f9e5c0a7\",\"mode\":\"100644\"},{\"path\":\"src/org/trillionnium/hepta/local/WebFlightNativeStability.java\",\"bytes\":23349,\"sha256\":\"503078f251696fb542912e5270efca13439ebcece4db8b3473e7fcb543b4fc2d\",\"git_blob_sha\":\"5d41e41c7e6c447f4dba598a12f21673c168603b\",\"mode\":\"100644\"}],\"projection_origins\":[{\"name\":\"WebEvidenceClient.java\",\"bytes\":20815,\"sha256\":\"96eb9307241ec3f5ad33dab37e894f9ddbcbf228c0bc48169b53056f42dab943\",\"git_blob_sha\":\"80c8ef7b9ac6ecafd1471f6d7ad59b21d3ffbb72\",\"path\":\"src/org/trillionnium/hepta/local/WebEvidenceClient.java\"},{\"name\":\"WebFlightSession.java\",\"bytes\":42734,\"sha256\":\"7f3c7fd872e9901026ad7471dfc9a3e68d2c987eb1931896f80ea0f2acd6f4e1\",\"git_blob_sha\":\"8283d4e83b7cf13c9deb7e55c6d26f26053e11cc\",\"path\":\"src/org/trillionnium/hepta/local/WebFlightSession.java\"},{\"name\":\"HeptaAccessibilityService.java\",\"bytes\":129287,\"sha256\":\"53dc2765f2f0504a4ea16618a2e0b44c0d443dceeb3834f030098ae2cea26fba\",\"git_blob_sha\":\"6200e5325ec1397abd73e9bfa99235c7b063935d\",\"path\":\"src/org/trillionnium/hepta/local/HeptaAccessibilityService.java\"}],\"methods\":[{\"origin\":\"client\",\"marker\":\"    synchronized WebEvidenceReceipt capture(\",\"bytes\":900,\"sha256\":\"c7de9edd5a83b975e4f8d5c3ededa8875207ac5cfe083110794922dddfdc1a5a\"},{\"origin\":\"client\",\"marker\":\"    synchronized WebEvidenceReceipt armObservedLink(\",\"bytes\":2614,\"sha256\":\"74d7e500d353fb623caa7a01d5f0202e8b09c68ed207d0309b9d136e50af0af6\"},{\"origin\":\"client\",\"marker\":\"    private long expiry(\",\"bytes\":203,\"sha256\":\"d4890058d118af00c912dd1aabf2e53cd7c73992a50f94897ce7fec0fbf00d7a\"},{\"origin\":\"client\",\"marker\":\"    private JSONObject common(\",\"bytes\":764,\"sha256\":\"ee1b3c76e2edb6339d08bfbeb54393ba00f81d44f4a0d298ac4af5d939a2a348\"},{\"origin\":\"session\",\"marker\":\"    private static final class ShoppingDispatch {\",\"bytes\":1246,\"sha256\":\"fde5d00260590d230c09ced6e13fce5bcb086be09cb837cf8b8ea21c1d0d9e04\"},{\"origin\":\"session\",\"marker\":\"    private static final class PendingNavigation {\",\"bytes\":600,\"sha256\":\"19ce08bdf233b7eb2024e1f26ddb09d8736fe21ad8529e5d00906fb53809de32\"},{\"origin\":\"session\",\"marker\":\"    void requireDispatch(\",\"bytes\":493,\"sha256\":\"843d3221bef5ff6e28b93ea14422bc2f04334d834aa051bdde38c39c794c114e\"},{\"origin\":\"session\",\"marker\":\"    WebRegionNativeBridge nativeRegionForDispatch(\",\"bytes\":501,\"sha256\":\"331346fa7420e7c814c017f31c241e9075b44941a27f41fa6c53d402f09382aa\"},{\"origin\":\"session\",\"marker\":\"    void acceptNativeRegionCheck(\",\"bytes\":544,\"sha256\":\"68f06e44ab5ff5f8a24bc5f3b3ef4273a928f6a793909879bc9538b80171ab28\"},{\"origin\":\"session\",\"marker\":\"    private ShoppingDispatch requireShoppingDispatch(\",\"bytes\":727,\"sha256\":\"2d2d551244e6039663a8057c37c8afdfef49a06ee68527abc980115e2e26029a\"},{\"origin\":\"session\",\"marker\":\"    void beforeNativeClickInvocation(\",\"bytes\":2133,\"sha256\":\"7a3996607f43684e15fef210e7a23ddca4654c5ad5d5904963e7a78b14ddc861\"},{\"origin\":\"session\",\"marker\":\"    private static String actionKey(\",\"bytes\":125,\"sha256\":\"6bef04d6accf4fdd30e1ff2a91a1ef0dacb8345df11563388a7f977f57a2d77f\"},{\"origin\":\"session\",\"marker\":\"    void modelActionOutcome(\",\"bytes\":3839,\"sha256\":\"03cf7a6908fbd3d19ee09bcd44450f26b61ef3ceba9cbce3ac399bdf5aad55df\"},{\"origin\":\"service\",\"marker\":\"    static final class NativeRegionCheck {\",\"bytes\":2247,\"sha256\":\"414058eac08807c16cfb3a972c38c16d84397e9e5a73563011d33d3f55f42c42\"},{\"origin\":\"session\",\"marker\":\"    void beforeModelAction(\",\"bytes\":6266,\"sha256\":\"1a309ee0bd72f739375cad2a6a10d30a13a3830db14e44e767f9318e8b1c43ae\"}],\"changed_methods\":[{\"origin\":\"session\",\"marker\":\"    void beforeNativeClickInvocation(\",\"before\":{\"bytes\":1514,\"sha256\":\"841dc6a1178c9a86c0a9f3227ea6dfc525784ab36bd931ec9f41209b83d899a1\",\"git_blob_sha\":\"ba8ec0a696537c84405569bfe5633dcbfcf5f5d5\"},\"after\":{\"bytes\":2133,\"sha256\":\"7a3996607f43684e15fef210e7a23ddca4654c5ad5d5904963e7a78b14ddc861\",\"git_blob_sha\":\"dec7a7df3f6cfc5568bd7471e5b29cedfec28071\"}},{\"origin\":\"session\",\"marker\":\"    void modelActionOutcome(\",\"before\":{\"bytes\":3779,\"sha256\":\"a9681d0613460a0c835a8dd906556acd728f220ac92b7c39a0544587ccf15336\",\"git_blob_sha\":\"4b10afec559b85c35055c5c4470120e812e41e69\"},\"after\":{\"bytes\":3839,\"sha256\":\"03cf7a6908fbd3d19ee09bcd44450f26b61ef3ceba9cbce3ac399bdf5aad55df\",\"git_blob_sha\":\"e66be0eb79392fe39bad8a3e4e05c573912cf577\"}},{\"origin\":\"session\",\"marker\":\"    void beforeModelAction(\",\"before\":{\"bytes\":5636,\"sha256\":\"cffbc4af647a1848f1c64be33a9904c1f01eb00c210f8468ecab70f5765085c5\",\"git_blob_sha\":\"92954ae0adcf8d3e3461d216dbb9a5a73359ad2f\"},\"after\":{\"bytes\":6266,\"sha256\":\"1a309ee0bd72f739375cad2a6a10d30a13a3830db14e44e767f9318e8b1c43ae\",\"git_blob_sha\":\"1c7b2b965f6bc4356e9b02808e7c468e0bebe0b4\"}}],\"type_only_replacements\":[{\"before\":\"    private PhoneObservation current;\",\"after\":\"    private PhoneObservation current;\\n    private WebEvidenceReceipt currentCapture;\\n    private WebFlightNativeStability.Permit flightNativePermit;\\n    private HeptaAccessibilityService.FlightNativeCheck flightNativeCheck;\\n    private final java.util.concurrent.atomic.AtomicBoolean flightNativeEntered=new java.util.concurrent.atomic.AtomicBoolean();\\n    private final java.util.Set<String> flightNativeAttemptedRuns=new java.util.HashSet<String>();\",\"count\":1},{\"before\":\"        client=new WebEvidenceClientArmProjection(binding,source);\",\"after\":\"        client=new WebEvidenceClientArmProjection(binding,source);currentCapture=source;\",\"count\":1},{\"before\":\"    static final class HeptaAccessibilityService {\",\"after\":\"    /** The dormant Flight type surface is explicit. It cannot construct a\\n     * permit or satisfy a native check. Shopping null follows the production\\n     * prepare predicate; the real top-level pure class is compiled separately\\n     * with its complete actual44-source closure and exercised by Web cases. */\\n    static final class WebFlightNativeStability {\\n        private WebFlightNativeStability(){throw new AssertionError(\\\"type only\\\");}\\n        static final class Permit {\\n            private Permit(){throw new AssertionError(\\\"no synthetic Flight permit\\\");}\\n            boolean matches(PhoneObservation frame,ActionDecision action,String run){throw new AssertionError(\\\"Flight not exercised here\\\");}\\n            JSONObject domEvidence(){throw new AssertionError(\\\"Flight not exercised here\\\");}\\n        }\\n        static Permit prepare(WebTaskDomain domain,PhoneObservation frame,ActionDecision action,String run,\\n                              WebEvidenceReceipt before,WebEvidenceReceipt after){\\n            if(domain==null||domain.flight==null)return null;\\n            throw new AssertionError(\\\"Flight capability is outside these unchanged Shopping ARM cases\\\");\\n        }\\n    }\\n    static final class HeptaAccessibilityService {\\n        static final class FlightNativeCheck {\\n            final long checkedAt;\\n            private FlightNativeCheck(){throw new AssertionError(\\\"no synthetic Flight native token\\\");}\\n            boolean matches(PhoneObservation frame,WebFlightNativeStability.Permit permit){throw new AssertionError(\\\"Flight not exercised here\\\");}\\n            JSONObject evidence(){throw new AssertionError(\\\"Flight not exercised here\\\");}\\n        }\",\"count\":1}],\"successor_metadata\":{\"schema\":\"hepta.main56-wire4-current-source-projection.v1\",\"prior_actual_input\":{\"bytes\":935559,\"sha256\":\"f9577768563f5fbf88bf77b0d484038c7ccd87b07d0ae5a79fb55ef92c987d4e\",\"git_blob_sha\":\"d3390ca0395e8f925f7c3b93cf502f967ab6a72f\"},\"aggregate\":{\"bytes\":1427055,\"sha256\":\"c1cc7cc16eef4c3a34131ee719101a69db080b76e72c98f03248036fc6fd628f\",\"git_blob_sha\":\"0803dec4b6acc359b810bb79ca6fdd01ada69a8c\"},\"source_inventory_sha256\":\"ca24673843908c7f9343c949af64b8393e69ce53605128782036ae9ce9d1f46e\",\"original_consumer_and_arm_case_sources_unchanged\":true,\"original_factory_and_actual_ax_unchanged\":true,\"projected_method_count\":15,\"changed_actual_method_count\":3,\"additional_actual_pure_compilation_inputs\":[{\"path\":\"src/org/trillionnium/hepta/local/CsairCityPicker.java\",\"bytes\":10363,\"sha256\":\"699f1eebe2db1ae4d7973f95f51c342748c24d767efd6f1a998d27f60c9b339f\",\"git_blob_sha\":\"9f70cfcbe936d659882e5a5ee029324ac17b343c\"},{\"path\":\"src/org/trillionnium/hepta/local/CsairFlightForm.java\",\"bytes\":15870,\"sha256\":\"27c88417bbfffc9b67d7a0a4cef896c1499b56fadb326e4985c84f5dd2cb0ef8\",\"git_blob_sha\":\"349052c61a86d89d208dc7897a72285035c67e97\"},{\"path\":\"src/org/trillionnium/hepta/local/DecisionGrammar.java\",\"bytes\":30605,\"sha256\":\"236d22187abfe777705d337241e310dd617b1c4c21ae39df4f52d960a1e106ca\",\"git_blob_sha\":\"b2b1aba87d179ed9054baa25227380825510baf0\"},{\"path\":\"src/org/trillionnium/hepta/local/MiPublicProductPage.java\",\"bytes\":17440,\"sha256\":\"aaddee9837555083ec1d796b67a2cfc37a280b023b12b2dbd4e474d47586ac8b\",\"git_blob_sha\":\"4d38f27e602302f71ecbf1c4e2e4fcb367fa9fe0\"},{\"path\":\"src/org/trillionnium/hepta/local/NotesCompletionEvidence.java\",\"bytes\":18644,\"sha256\":\"1ce2e8dfc588ae51545f88a0eccb2002cfd91f647db0225fd95398ff04157f7d\",\"git_blob_sha\":\"5da9ae144dca74f67916729ec5b7d2b6ae0dbc00\"},{\"path\":\"src/org/trillionnium/hepta/local/NotesCreateWorkflow.java\",\"bytes\":21099,\"sha256\":\"0995cd9a7f5897d2dab5827a432eaa13cc7d8d6363ffda415baa6d566d80d80d\",\"git_blob_sha\":\"e39942a3897444cdeb57b5642c3ea8c58213f362\"},{\"path\":\"src/org/trillionnium/hepta/local/TaskCompletionGate.java\",\"bytes\":49971,\"sha256\":\"ad417d98fbd7b12bf4373270a1206c11984682c9f35b7b4a5179bb9fbff7ba98\",\"git_blob_sha\":\"48323262aaf10962f0a481cafc18c56bc82e936b\"},{\"path\":\"src/org/trillionnium/hepta/local/WebFlightDomain.java\",\"bytes\":43483,\"sha256\":\"a1be374d093186d8ae58c77aaa2a65e289ff3a9d89c31bae7eef9f223672c6a5\",\"git_blob_sha\":\"da12c492e77b165efa68fce434f778ca2ca22361\"},{\"path\":\"src/org/trillionnium/hepta/local/WebShoppingDomain.java\",\"bytes\":31717,\"sha256\":\"bbf256e37eb5cc3a1619371e9c29dc5f7af3139eeb4f602f602cf0f05551bf92\",\"git_blob_sha\":\"78c1c4d616a815dbf31b214f0fb74754745c967c\"},{\"path\":\"src/org/trillionnium/hepta/local/WebTaskDomain.java\",\"bytes\":8817,\"sha256\":\"fe2eb43d1546ae56803133b86fc959f3a5b5e036821553dddfc93fe02bdc9b98\",\"git_blob_sha\":\"c64cbf8cbcfbcb9c5734049613d575f45380cb09\"},{\"path\":\"src/org/trillionnium/hepta/local/CsairCalendar.java\",\"bytes\":20890,\"sha256\":\"9bc3019994e12493a6c2c6882a983c0021cb875ad6159033777c2c2c73618434\",\"git_blob_sha\":\"d763010ffe1281775ba772e9498b974b7af14be1\"},{\"path\":\"src/org/trillionnium/hepta/local/WebFlightProgress.java\",\"bytes\":16832,\"sha256\":\"47630c3e36b56470ebdb8353b24c68f94bf6274d7fefc08133cd7a78946a0691\",\"git_blob_sha\":\"08e5a189ee8b2f16980f7f1e9dc08ae8454ef02d\"},{\"path\":\"src/org/trillionnium/hepta/local/WebFlightNativeStability.java\",\"bytes\":23349,\"sha256\":\"503078f251696fb542912e5270efca13439ebcece4db8b3473e7fcb543b4fc2d\",\"git_blob_sha\":\"5d41e41c7e6c447f4dba598a12f21673c168603b\"}],\"flight_type_surface_only\":true,\"flight_type_surface_cannot_construct_token\":true,\"actual_flight_native_dispatch_tested_here\":false,\"live_native_or_binder_executed\":false,\"assertions_changed\":false,\"host_executed\":false,\"phone_actions\":0,\"business_verified\":false}}")

def need(value, why):
    if not value:
        raise RuntimeError(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def strict_json(raw):
    def pairs(values):
        out = {}
        for key, value in values:
            need(key not in out, "duplicate JSON key")
            out[key] = value
        return out
    def no_number(value):
        raise ValueError("unexpected floating point or non-finite metadata")
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                      parse_float=no_number, parse_constant=no_number)

def identity(st):
    return [st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns]

def read_regular(path, expected=None, limit=4194304):
    path = Path(path)
    need(path.is_absolute(), "absolute source path required")
    for parent in path.parents:
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "source ancestor is not an ordinary directory")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
         "bounded single-link regular file required")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        need(identity(before) == identity(opened), "source identity changed before open")
        chunks = []
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - sum(map(len, chunks))))
            if not chunk:
                break
            chunks.append(chunk)
            need(sum(map(len, chunks)) <= limit, "source exceeds byte limit")
        raw = b"".join(chunks)
        after_open = os.fstat(fd)
    finally:
        os.close(fd)
    after = path.lstat()
    need(identity(before) == identity(after_open) == identity(after) and len(raw) == before.st_size,
         "source changed across exact read")
    facts = {"path": str(path), "bytes": len(raw), "sha256": sha(raw), "identity": identity(after)}
    if expected is not None:
        need(type(expected["bytes"]) is int and len(raw) == expected["bytes"] and sha(raw) == expected["sha256"],
             "source full bytes/SHA mismatch: " + str(path))
    return raw, facts

def unchanged(facts):
    _, current = read_regular(facts["path"], facts)
    need(current == facts, "original bytes or identity changed: " + facts["path"])

def checked_text(row):
    need(type(row["raw_utf8"]) is str and type(row["bytes"]) is int, "exact UTF8 member")
    raw = row["raw_utf8"].encode("utf-8", "strict")
    need(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "raw member pin mismatch")
    return raw

def java_block(source, marker):
    need(source.count(marker) == 1, "unique original Java marker required")
    start = source.index(marker)
    at = source.index("{", start)
    depth, quote, line, block, escape = 0, None, False, False, False
    i = at
    while i < len(source):
        c = source[i]
        nxt = source[i+1] if i+1 < len(source) else ""
        if line:
            if c == "\n":
                line = False
        elif block:
            if c == "*" and nxt == "/":
                block = False
                i += 1
        elif quote is not None:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == quote:
                quote = None
        elif c == "/" and nxt == "/":
            line = True
            i += 1
        elif c == "/" and nxt == "*":
            block = True
            i += 1
        elif c in ("'", '"'):
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[start:i+1]
        i += 1
    raise RuntimeError("unclosed Java method")

def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    _, facts = read_regular(path, {"bytes": len(raw), "sha256": sha(raw)})
    return facts

def encoded(value):
    return (json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode("utf-8")

def git_blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode("ascii")+b"\0"+raw).hexdigest()

def check_pin(raw,pin,why):
    need(type(pin["bytes"]) is int and len(raw)==pin["bytes"] and sha(raw)==pin["sha256"],why)
    if "git_blob_sha" in pin:need(git_blob(raw)==pin["git_blob_sha"],why+" Git")
    return raw

def exact_source_tree(root):
    values,facts={},[]
    need(root.is_dir() and not root.is_symlink(),"existing current source tree")
    for path in sorted(root.rglob("*")):
        need(not path.is_symlink(),"no current source symlink")
        if path.is_dir():continue
        name=path.relative_to(root).as_posix()
        need(name not in values and ".." not in Path(name).parts,"safe unique current member")
        raw,fact=read_regular(path);values[name]=raw;facts.append(fact)
    return values,facts

def derive_current_input(base_raw,data,current_sources):
    delta=CURRENT_DELTA
    check_pin(base_raw,delta["base"],"actual55 derived input")
    paths={"client":"WebEvidenceClient.java","session":"WebFlightSession.java","service":"HeptaAccessibilityService.java"}
    targets={"client":"tests/main55-wire4/WebEvidenceClientArmProjection.java",
             "session":"tests/main55-wire4/WebFlightSessionArmProjection.java",
             "service":"tests/main55-wire4/WebFlightSessionArmProjection.java"}
    old_origins={row["name"]:row["raw_utf8"] for row in data["projection_originals"]}
    new_origins={}
    for row in delta["projection_origins"]:
        raw=check_pin(current_sources[row["path"]],row,"current actual projection original")
        new_origins[row["name"]]=raw.decode("utf-8","strict")
    method_changes=[]
    for projection in data["projections"]:
        name=paths[projection["origin"]]
        old_body=java_block(old_origins[name],projection["marker"])
        new_body=java_block(new_origins[name],projection["marker"])
        if old_body!=new_body:
            matches=[row for row in data["compile_files"] if row["path"]==targets[projection["origin"]]]
            need(len(matches)==1 and matches[0]["raw_utf8"].count(old_body)==1,"one exact current-method projection")
            matches[0]["raw_utf8"]=matches[0]["raw_utf8"].replace(old_body,new_body,1)
            method_changes.append({"origin":projection["origin"],"marker":projection["marker"],
                "before":{"bytes":len(old_body.encode("utf-8")),"sha256":sha(old_body.encode("utf-8")),"git_blob_sha":git_blob(old_body.encode("utf-8"))},
                "after":{"bytes":len(new_body.encode("utf-8")),"sha256":sha(new_body.encode("utf-8")),"git_blob_sha":git_blob(new_body.encode("utf-8"))}})
        projection["bytes"]=len(new_body.encode("utf-8"));projection["sha256"]=sha(new_body.encode("utf-8"))
    need(method_changes==delta["changed_methods"] and data["projections"]==delta["methods"],
         "only three current Session methods changed; all15 actual blocks are fixed")
    target=next(row for row in data["compile_files"] if row["path"]==targets["session"])
    before=target["raw_utf8"];value=before
    for change in delta["type_only_replacements"]:
        need(change["count"]==1 and value.count(change["before"])==1,"exact dormant Flight type surface")
        value=value.replace(change["before"],change["after"],1)
    reverse=value
    for change in reversed(delta["type_only_replacements"]):
        need(reverse.count(change["after"])==1,"exact reverse dormant Flight type surface")
        reverse=reverse.replace(change["after"],change["before"],1)
    need(reverse==before,"no production method or old assertion rewritten by type completion")
    target["raw_utf8"]=value
    for row in data["compile_files"]:
        if row["path"].startswith("src/"):
            row["raw_utf8"]=current_sources[row["path"]].decode("utf-8","strict")
        raw=row["raw_utf8"].encode("utf-8","strict")
        row["bytes"]=len(raw);row["sha256"]=sha(raw)
        if "git_blob_sha" in row:row["git_blob_sha"]=git_blob(raw)
    for pin in delta["pure_compilation_inputs"]:
        raw=check_pin(current_sources[pin["path"]],pin,"actual current pure compilation member")
        if any(row["path"]==pin["path"] for row in data["compile_files"]):continue
        data["compile_files"].append({"path":pin["path"],"bytes":pin["bytes"],"sha256":pin["sha256"],
            "git_blob_sha":pin["git_blob_sha"],"raw_utf8":raw.decode("utf-8","strict"),
            "origin":"exact Main56 materialized production source; additional compilation closure only"})
    for row in data["projection_originals"]:
        row["raw_utf8"]=new_origins[row["name"]]
        raw=row["raw_utf8"].encode("utf-8","strict");row["bytes"]=len(raw);row["sha256"]=sha(raw)
        if "git_blob_sha" in row:row["git_blob_sha"]=git_blob(raw)
    data["expected"]["java_source_count"]=len(data["compile_files"])
    data["current_source_successor"]=delta["successor_metadata"]
    raw=encoded(data);check_pin(raw,delta["result"],"complete current51-file input")
    return raw,data

# All immutable input and tool reads precede the first mutation.
stage_raw = globals().get("__stage_source__")
need(type(stage_raw) is bytes and len(stage_raw) > 0, "loader must pass its exact hashed compiled stage bytes")
packed, input_facts = read_regular(CONFIG["input_path"], {"bytes": CONFIG["input_bytes"], "sha256": CONFIG["input_sha256"]})
raw = gzip.decompress(packed)
need(len(raw) == CONFIG["decoded_bytes"] and sha(raw) == CONFIG["decoded_sha256"], "full decoded candidate pin")
data = strict_json(raw)
original_decoded_facts = {"bytes": len(raw), "sha256": sha(raw)}
# One explicit fixture type adapter. The original compressed input stays immutable.
adapter = CONFIG["fixture_type_adapter"]
need(adapter["schema"] == "hepta.explicit-synthetic-map-json-adapter.v1"
     and adapter["path"] == "tests/main55-wire4/WebWire4SyntheticFactory.java"
     and adapter["count"] == 1 and adapter["production_sources_changed"] is False
     and adapter["assertions_changed"] is False, "fixed synthetic-only adapter scope")
targets = [row for row in data["compile_files"] if row["path"] == adapter["path"]]
need(len(targets) == 1, "one existing synthetic factory")
target = targets[0]
old_factory_raw = checked_text(target)
need(len(old_factory_raw) == adapter["original_factory"]["bytes"]
     and sha(old_factory_raw) == adapter["original_factory"]["sha256"]
     and target["raw_utf8"].count(adapter["before"]) == 1
     and adapter["after"] not in target["raw_utf8"], "exact old factory expression and bytes")
adapted_factory = target["raw_utf8"].replace(adapter["before"], adapter["after"])
need(adapted_factory.count(adapter["after"]) == 1
     and adapted_factory.replace(adapter["after"], adapter["before"]).encode("utf-8") == old_factory_raw,
     "single expression adaptation must reverse to exact original")
adapted_factory_raw = adapted_factory.encode("utf-8")
need(len(adapted_factory_raw) == adapter["compiled_factory"]["bytes"]
     and sha(adapted_factory_raw) == adapter["compiled_factory"]["sha256"], "exact adapted factory pin")
projection = data["factory_projection"]
need(projection["source_methods_modified"] is False
     and projection["factory_bytes"] == len(old_factory_raw)
     and projection["factory_sha256"] == sha(old_factory_raw)
     and projection["methods_sha256"] == adapter["original_methods_sha256"], "original projection provenance")
target["raw_utf8"] = adapted_factory
target["bytes"] = len(adapted_factory_raw)
target["sha256"] = sha(adapted_factory_raw)
projection["factory_bytes"] = target["bytes"]
projection["factory_sha256"] = target["sha256"]
projection["source_methods_modified"] = True
projection["compiled_methods_sha256"] = adapter["compiled_methods_sha256"]
projection["fixture_type_adapter"] = adapter
raw = (json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False)+"\n").encode("utf-8")
need(len(raw) == CONFIG["derived_bytes"] and sha(raw) == CONFIG["derived_sha256"],
     "entire derived input pin; all non-adapter bytes and metadata stay fixed")
# The explicit host provider must expose the production Map return type.
# JSONObject(Object) is a bean constructor; the prior JSONObject return type
# changed overload resolution inside an otherwise exact production method.
provider_adapter = CONFIG["provider_type_adapter"]
need(provider_adapter["schema"] == "hepta.explicit-host-provider-map-api-adapter.v1"
     and provider_adapter["path"] == "tests/main55-wire4/WebFlightSessionArmProjection.java"
     and len(provider_adapter["replacements"]) == 2
     and provider_adapter["production_sources_changed"] is False
     and provider_adapter["test_assertions_changed"] is False
     and "provider_type_adapter" not in data, "fixed provider-double return-type adapter")
provider_rows = [row for row in data["compile_files"] if row["path"] == provider_adapter["path"]]
need(len(provider_rows) == 1, "one original Session projection fixture")
provider_row = provider_rows[0]
provider_before = checked_text(provider_row)
need(len(provider_before) == provider_adapter["original"]["bytes"]
     and sha(provider_before) == provider_adapter["original"]["sha256"], "exact original provider double")
provider_text = provider_before.decode("utf-8")
for replacement in provider_adapter["replacements"]:
    need(replacement["count"] == 1 and provider_text.count(replacement["before"]) == 1
         and replacement["after"] not in provider_text, "one exact provider API replacement")
    provider_text = provider_text.replace(replacement["before"], replacement["after"])
provider_reverse = provider_text
for replacement in reversed(provider_adapter["replacements"]):
    need(provider_reverse.count(replacement["after"]) == 1, "unique reverse provider replacement")
    provider_reverse = provider_reverse.replace(replacement["after"], replacement["before"])
need(provider_reverse.encode("utf-8") == provider_before, "provider adapter reverses to exact prior fixture")
provider_bytes = provider_text.encode("utf-8")
need(len(provider_bytes) == provider_adapter["compiled"]["bytes"]
     and sha(provider_bytes) == provider_adapter["compiled"]["sha256"], "adapted provider full pin")
provider_row["raw_utf8"] = provider_text
provider_row["bytes"] = len(provider_bytes)
provider_row["sha256"] = sha(provider_bytes)
data["provider_type_adapter"] = provider_adapter
raw = (json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False)+"\n").encode("utf-8")
need(len(raw) == CONFIG["provider_adapted_bytes"] and sha(raw) == CONFIG["provider_adapted_sha256"],
     "entire second derived input pin; no other source or assertion may change")
# Bind the old successful run and every current595 source byte before deriving.
current_originals=[]
SOURCE=Path(CONFIG["current"]["source_root"]);MATERIALIZED=Path(CONFIG["current"]["materialized_root"])
need(SOURCE==MATERIALIZED/"source" and Path(CONFIG["root"]) not in MATERIALIZED.parents
     and MATERIALIZED not in Path(CONFIG["root"]).parents,"independent current source root")
aggregate_raw,aggregate_facts=read_regular(MATERIALIZED/"AGGREGATE.json",CONFIG["current"]["aggregate"])
current_originals.append(aggregate_facts)
aggregate=strict_json(aggregate_raw)
need(git_blob(aggregate_raw)==CONFIG["current"]["aggregate"]["git_blob_sha"],"current aggregate Git identity")
inventory_raw,inventory_facts=read_regular(MATERIALIZED/"SOURCE-INVENTORY.json",CONFIG["current"]["inventory"])
current_originals.append(inventory_facts)
current_sources,current_source_facts=exact_source_tree(SOURCE);current_originals.extend(current_source_facts)
need(len(current_sources)==595 and len(aggregate["inventory"]["files"])==595
     and set(current_sources)=={r["path"] for r in aggregate["inventory"]["files"]},"full595 current source membership")
for row in aggregate["inventory"]["files"]:check_pin(current_sources[row["path"]],row,"current source map member")
need(inventory_raw==encoded([{"path":name,"bytes":len(value),"sha256":sha(value)}
     for name,value in sorted(current_sources.items(),key=lambda item:Path(item[0]))]),"complete Path-ordered current inventory")
PRIOR_SUCCESS=Path(CONFIG["current"]["prior_root"])
prior_success_raw,prior_success_facts=read_regular(PRIOR_SUCCESS/"RESULT.json",CONFIG["current"]["prior_result"])
current_originals.append(prior_success_facts)
prior_success=json.loads(prior_success_raw.decode("utf-8","strict"))
need(prior_success["schema"]=="hepta.main55-wire4-focused-host-stage.v1" and prior_success["all_pass"] is True
     and prior_success["originals_and_written_sources_unchanged"] is True and prior_success["prior_failed_run_preserved"] is True
     and prior_success["root"]==str(PRIOR_SUCCESS),"actual55 original focused39 success")
need([(x["name"],x["exit_code"]) for x in prior_success["steps"]]==[("compile",0),("consumer",0),("arm",0)]
     and all(x["timed_out"] is False and x["forced_kill"] is False and x["exit_observed"] is True for x in prior_success["steps"]),
     "actual prior three normal processes")
prior_current_guards=list(prior_success["written_sources"])
for step in prior_success["steps"]:prior_current_guards.extend((step["stdout"],step["stderr"]))
for report in prior_success["reports"].values():prior_current_guards.append(report["original"])
need(len({p["path"] for p in prior_current_guards})==len(prior_current_guards),"distinct old success inputs and logs")
for pin in prior_current_guards:
    need(str(PRIOR_SUCCESS)+"/" in pin["path"] and Path(pin["path"]).is_relative_to(PRIOR_SUCCESS),"fixed old success tree only")
    _,facts=read_regular(pin["path"],pin);current_originals.append(facts)
old_input,old_input_facts=read_regular(PRIOR_SUCCESS/"INPUT.json",CONFIG["current"]["prior_input"])
current_originals.append(old_input_facts)
need(old_input==raw,"reconstructed original input equals actual55 output byte-for-byte")
raw,data=derive_current_input(raw,data,current_sources)
need(data["schema"] == "hepta.main55-wire4-host-input.v1" and data["root"] == CONFIG["input_scope_root"], "unchanged original candidate scope")
need(data["expected"] == {"java_source_count": 51, "consumer_cases": 20, "arm_cases": 19}, "fixed focused gates")
need(data["claims"] == {"android_compiled": False, "actual_binder_tested": False, "live_accessibility_tested": False,
                        "phone_actions": 0, "business_verified": False}, "bounded host-only claims")
files = data["compile_files"]
need(len(files) == 51 and sorted(row["path"] for row in files) == CONFIG["expected_paths"], "exact source membership")
by_path = {}
for row in files:
    name = row["path"]
    need(name not in by_path and not name.startswith("/") and ".." not in Path(name).parts and name.endswith(".java"),
         "unique safe Java member path")
    checked_text(row)
    by_path[name] = row
originals = {}
for row in data["projection_originals"]:
    need(row["name"] in ("WebEvidenceClient.java", "WebFlightSession.java", "HeptaAccessibilityService.java")
         and row["name"] not in originals and row["compiled_as_android_source"] is False, "actual projection origin")
    checked_text(row)
    originals[row["name"]] = row["raw_utf8"]
need(len(originals) == 3, "all actual Android method sources required")
origin_names = {"client": "WebEvidenceClient.java", "session": "WebFlightSession.java", "service": "HeptaAccessibilityService.java"}
projection_targets = {"client": "tests/main55-wire4/WebEvidenceClientArmProjection.java",
                      "session": "tests/main55-wire4/WebFlightSessionArmProjection.java",
                      "service": "tests/main55-wire4/WebFlightSessionArmProjection.java"}
need(len(data["projections"]) == 15, "fixed exact-method set")
for projection in data["projections"]:
    body = java_block(originals[origin_names[projection["origin"]]], projection["marker"])
    projected = java_block(by_path[projection_targets[projection["origin"]]]["raw_utf8"], projection["marker"])
    body_raw = body.encode("utf-8")
    need(body == projected and len(body_raw) == projection["bytes"] and sha(body_raw) == projection["sha256"],
         "projected method differs from actual production source")
factory_raw = checked_text(data["factory_original"])
need(data["factory_original"]["git"] == "0be198a917cbe3a3c6b2e4c8aeca7725771a842c"
     and sha(factory_raw) == "a6463d7705bde482d4436df6222b85bd985ba6b4a9ec460bf27219fcf201d940", "fixed original synthetic factory")
factory = factory_raw.decode("utf-8")
begin, end = "    static String rep(char value,int n)", "    static void current(ObservedLinkPermit p,long now,JSONObject b)"
need(factory.count(begin) == factory.count(end) == 1, "original factory anchors")
method_block = factory[factory.index(begin):factory.index(end)]
const_begin, const_end = '    static final String ROOT=', '    static void need('
constants = factory[factory.index(const_begin):factory.index(const_end)]
factory_target = by_path["tests/main55-wire4/WebWire4SyntheticFactory.java"]["raw_utf8"]
need(method_block.count(adapter["before"]) == 1 and adapter["after"] not in method_block,
     "one original factory Map boundary")
compiled_method_block = method_block.replace(adapter["before"], adapter["after"])
need(compiled_method_block.count(adapter["after"]) == 1
     and compiled_method_block.replace(adapter["after"], adapter["before"]) == method_block,
     "compiled factory methods reverse exactly to original")
need(factory_target.count(compiled_method_block) == 1 and factory_target.count(constants) == 1,
     "only the declared fixture type adapter may change original factory methods")
need(sha(method_block.encode("utf-8")) == data["factory_projection"]["methods_sha256"]
     and sha(compiled_method_block.encode("utf-8")) == data["factory_projection"]["compiled_methods_sha256"]
     and sha(constants.encode("utf-8")) == data["factory_projection"]["constants_sha256"], "factory exact original and adapted blocks")
ax_raw = checked_text(data["actual_ax"])
need(len(ax_raw) == 211683 and sha(ax_raw) == "83696c2a0838d4821e5bcedc3034c0f473adfcdc0443cc078ef58bcf8edac0c7",
     "complete original native AX required")
org_ready_raw, org_ready_facts = read_regular(CONFIG["orgjson_ready"]["path"], CONFIG["orgjson_ready"])
org_ready = strict_json(org_ready_raw)
need(org_ready["schema"] == "hepta.fixed-host-orgjson-ready.v1" and org_ready["verified"] is True
     and org_ready["coordinate"] == "org.json:json:20240303"
     and org_ready["artifact"]["verified"] is True
     and org_ready["artifact"]["path"] == CONFIG["json"]["path"]
     and org_ready["artifact"]["bytes"] == CONFIG["json"]["bytes"]
     and org_ready["artifact"]["sha256"] == CONFIG["json"]["sha256"]
     and org_ready["artifact"]["http_status"] == 200 and org_ready["artifact"]["redirects_followed"] == 0
     and org_ready["artifact"]["tls_verification"] is True and org_ready["phone_contacted"] is False,
     "actual completed host JSON provenance")
tool_facts = {"orgjson_ready": org_ready_facts}
for name in ("java", "javac", "json"):
    _, tool_facts[name] = read_regular(CONFIG[name]["path"], CONFIG[name])
    if name != "json":
        need(os.access(CONFIG[name]["path"], os.X_OK), "original JDK executable")
# Preserve this actual failed run, its 45 written inputs and all four JVM logs.
# Exact SHA binds the original duration-bearing JSON; it is not a new test result.
prior_raw, prior_facts = read_regular(CONFIG["prior_failure"]["path"], CONFIG["prior_failure"])
prior = json.loads(prior_raw.decode("utf-8", "strict"))
need(prior["schema"] == "hepta.main55-wire4-focused-host-stage.v1"
     and prior["root"] == CONFIG["prior_failure"]["root"] and prior["all_pass"] is False
     and prior["originals_unchanged_after_failure"] is True and prior["reports"] == {}
     and prior["error"]["message"] == "actual JVM step failed: consumer",
     "fixed actual first-run failure")
need([(item["name"], item["exit_code"]) for item in prior["steps"]] == [("compile", 0), ("consumer", 1)]
     and all(item["timed_out"] is False and item["forced_kill"] is False and item["exit_observed"] is True
             for item in prior["steps"]) and len(prior["written_sources"]) == 45,
     "actual compile success and consumer failure; ARM never ran")
need(prior["steps"][1]["stderr"]["bytes"] == 810
     and prior["steps"][1]["stderr"]["sha256"] == "19fb00ce592cdb2fbe24d59a4a9083c57c9248077783d35a9939d90fa1c065c9",
     "original noncanonical binding failure log")
prior_guards = [prior_facts]
prior_rows = list(prior["written_sources"])
for step in prior["steps"]:
    prior_rows.extend((step["stdout"], step["stderr"]))
need(len(prior_rows) == 49 and len({row["path"] for row in prior_rows}) == 49, "fixed distinct prior sources and logs")
for row in prior_rows:
    need(row["path"].startswith(CONFIG["prior_failure"]["root"]+"/"), "only the fixed prior output tree")
    _, facts = read_regular(row["path"], row)
    prior_guards.append(facts)
need(len(prior_guards) == 50, "prior result plus 45 source files and four logs")
second_prior_raw, second_prior_facts = read_regular(CONFIG["second_prior_failure"]["path"], CONFIG["second_prior_failure"])
second_prior = json.loads(second_prior_raw.decode("utf-8", "strict"))
need(second_prior["schema"] == "hepta.main55-wire4-focused-host-stage.v1"
     and second_prior["root"] == CONFIG["second_prior_failure"]["root"] and second_prior["all_pass"] is False
     and second_prior["originals_unchanged_after_failure"] is True
     and second_prior["prior_failed_run_preserved"] is True
     and second_prior["error"]["message"] == "actual JVM step failed: arm",
     "fixed second actual failure; first failure remains preserved")
need([(item["name"], item["exit_code"]) for item in second_prior["steps"]]
         == [("compile", 0), ("consumer", 0), ("arm", 1)]
     and all(item["timed_out"] is False and item["forced_kill"] is False and item["exit_observed"] is True
             for item in second_prior["steps"]) and len(second_prior["written_sources"]) == 45,
     "actual second compile/consumer successes and ARM failure")
need(set(second_prior["reports"]) == {"consumer"}
     and second_prior["reports"]["consumer"]["report"]["all_pass"] is True
     and second_prior["reports"]["consumer"]["report"]["case_count"] == 20
     and second_prior["reports"]["consumer"]["report"]["assertion_count"] == 60
     and second_prior["steps"][2]["stderr"]["bytes"] == 760
     and second_prior["steps"][2]["stderr"]["sha256"] == "e93ae298373f2222ce722af38f4317f9cbafa6e8b7eb04792b4646acec8b8e03",
     "exact actual consumer result and provider-double overload failure log")
second_rows = list(second_prior["written_sources"])
for step in second_prior["steps"]:
    second_rows.extend((step["stdout"], step["stderr"]))
second_rows.append(second_prior["reports"]["consumer"]["original"])
need(len(second_rows) == 52 and len({row["path"] for row in second_rows}) == 52,
     "second run sources, six logs and actual consumer result")
prior_guards.append(second_prior_facts)
for row in second_rows:
    need(row["path"].startswith(CONFIG["second_prior_failure"]["root"]+"/"), "only the second fixed prior tree")
    _, facts = read_regular(row["path"], row)
    prior_guards.append(facts)
need(len(prior_guards) == 103 and len({row["path"] for row in prior_guards}) == 103,
     "both actual failures and their 101 original source/log/report files")
ROOT = Path(CONFIG["root"])
ROOT.mkdir(mode=0o700)  # FIRST MUTATION. Outside handler: a late entry never writes winner artifacts.

steps, written, error, reports = [], [], None, {}
result = {"schema": "hepta.main56-wire4-focused-host-stage.v1", "root": str(ROOT), "all_pass": False,
          "source_checkpoint_git": CONFIG["current"]["aggregate"]["git_blob_sha"], "input": input_facts,
          "prior_source_checkpoint_git": data["source_checkpoint_git"],
          "current_source_inventory_sha256": CONFIG["current"]["inventory"]["sha256"],
          "source_file_count":595,"source_root":str(SOURCE),"current_source_successor":data["current_source_successor"],
          "prior_successful_focused_result":prior_success_facts,"prior_successful_run_preserved":False,
          "original_decoded_input": original_decoded_facts,
          "derived_input": {"bytes": len(raw), "sha256": sha(raw)},
          "fixture_type_adapter": adapter, "provider_type_adapter": provider_adapter,
          "prior_failure": prior_facts, "second_prior_failure": second_prior_facts,
          "prior_preservation_file_count": len(prior_guards), "prior_failed_run_preserved": False,
          "stage_source": {"bytes": len(stage_raw), "sha256": sha(stage_raw)},
          "java_sources": 51, "pure_production_sources":44, "exact_method_projection_count": 15,
          "actual_ax": {"bytes": len(ax_raw), "sha256": sha(ax_raw)},
          "tools": tool_facts, "steps": steps, "reports": reports,
          "android_compiled": False, "binder_transport_tested": False, "native_accessibility_tested": False,
          "phone_actions": 0, "business_verified": False}
def run_step(name, argv, timeout):
    started = time.monotonic()
    out_path, err_path = ROOT/(name+".stdout"), ROOT/(name+".stderr")
    process, timed_out, forced, code = None, False, False, None
    with out_path.open("xb") as stdout, err_path.open("xb") as stderr:
        process = subprocess.Popen(argv, cwd=str(ROOT), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   start_new_session=True, env={"PATH": "/usr/bin:/bin"})
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
            # Every exceptional wait path owns only this newly created process
            # group. An unobserved/forced exit can never satisfy a passing step.
            if process.poll() is None:
                forced = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    code = process.wait(timeout=5)
    _, out = read_regular(out_path, limit=2097152)
    _, err = read_regular(err_path, limit=2097152)
    item = {"name": name, "argv": argv, "pid": process.pid, "exit_code": code, "timed_out": timed_out,
            "forced_kill": forced, "exit_observed": process.poll() is not None, "elapsed_seconds": time.monotonic()-started,
            "stdout": out, "stderr": err}
    steps.append(item)
    need(code == 0 and not timed_out and not forced and process.poll() is not None, "actual JVM step failed: "+name)

try:
    written.append(write_new(ROOT/"stage.py", stage_raw))
    written.append(write_new(ROOT/"INPUT.json", raw))
    written.append(write_new(ROOT/"CURRENT-DELTA.json", encoded(CURRENT_DELTA)))
    source_paths = []
    for row in files:
        destination = ROOT/"source"/row["path"]
        written.append(write_new(destination, row["raw_utf8"].encode("utf-8")))
        source_paths.append(str(destination))
    for name, original in originals.items():
        written.append(write_new(ROOT/"projection-originals"/name, original.encode("utf-8")))
    written.append(write_new(ROOT/"projection-originals"/"WebScopedNavigationHostTest.java", factory_raw))
    fixture = ROOT/"fixtures"/"actual-mi-ax.xml"
    written.append(write_new(fixture, ax_raw))
    classes = ROOT/"classes"
    classes.mkdir(mode=0o700)
    javac = [CONFIG["javac"]["path"], "--release", "8", "-proc:none", "-encoding", "UTF-8", "-Xlint:all", "-Werror",
             "-cp", CONFIG["json"]["path"], "-d", str(classes)] + sorted(source_paths)
    run_step("compile", javac, 180)
    classpath = str(classes)+os.pathsep+CONFIG["json"]["path"]
    for short, main, count, schema in (
        ("consumer", "WebWire4ConsumerHostTest", 20, "hepta.main55-wire4-consumer-host-test.v1"),
        ("arm", "WebArmDispatchHostTest", 19, "hepta.main55-arm-dispatch-host-test.v1"),
    ):
        output = ROOT/(short+"-RESULT.json")
        run_step(short, [CONFIG["java"]["path"], "-cp", classpath, "org.trillionnium.hepta.local."+main,
                         str(fixture), str(output)], 120)
        actual, actual_facts = read_regular(output, limit=65536)
        report = strict_json(actual)
        need(report["schema"] == schema and report["all_pass"] is True and type(report["case_count"]) is int
             and report["case_count"] == count and type(report["assertion_count"]) is int and report["assertion_count"] > count,
             "actual Java case report")
        need(report["cases"]==prior_success["reports"][short]["report"]["cases"]
             and report["assertion_count"]==prior_success["reports"][short]["report"]["assertion_count"],
             "original focused case names/order and all assertions retained")
        need(report["android_compiled"] is False and report["phone_actions"] == 0 and report["business_verified"] is False,
             "host result cannot promote Android/phone/business scope")
        reports[short] = {"original": actual_facts, "report": report}
    need(len(steps) == 3, "one compile and two focused actual JVM runs")
    for facts in written + [input_facts] + list(tool_facts.values()) + prior_guards + current_originals:
        unchanged(facts)
    need(exact_source_tree(SOURCE)==(current_sources,current_source_facts),"all current595 source bytes and identities unchanged")
    result["current_source_tree_unchanged"] = True
    result["prior_successful_run_preserved"] = True
    result["originals_and_written_sources_unchanged"] = True
    result["prior_failed_run_preserved"] = True
    result["compiled_class_count"] = len(list(classes.rglob("*.class")))
    result["all_pass"] = True
except BaseException as failure:
    error = {"type": type(failure).__name__, "message": str(failure), "traceback": traceback.format_exc()}
    result["error"] = error
    try:
        for facts in [input_facts] + list(tool_facts.values()) + prior_guards + current_originals:
            unchanged(facts)
        need(exact_source_tree(SOURCE)==(current_sources,current_source_facts),"current source tree remains exact after failure")
        result["current_source_tree_unchanged"] = True
        result["prior_successful_run_preserved"] = True
        result["originals_unchanged_after_failure"] = True
        result["prior_failed_run_preserved"] = True
    except BaseException as source_failure:
        result["originals_unchanged_after_failure"] = False
        result["source_guard_error"] = str(source_failure)
result["written_sources"] = [{key: value for key, value in facts.items() if key != "identity"} for facts in written]
result_bytes = (json.dumps(result, ensure_ascii=False, indent=2)+"\n").encode("utf-8")
result_facts = write_new(ROOT/"RESULT.json", result_bytes)
summary = {"schema": "hepta.main56-wire4-focused-host-summary.v1", "all_pass": result["all_pass"],
           "result": result_facts, "steps": [{"name": s["name"], "exit_code": s["exit_code"],
                   "timed_out": s["timed_out"], "forced_kill": s["forced_kill"]} for s in steps],
           "consumer_cases": reports.get("consumer", {}).get("report", {}).get("case_count"),
           "arm_cases": reports.get("arm", {}).get("report", {}).get("case_count"),
           "error": error, "android_compiled": False, "phone_actions": 0, "business_verified": False}
write_new(ROOT/"SUMMARY.json", (json.dumps(summary, ensure_ascii=False, indent=2)+"\n").encode("utf-8"))
print(json.dumps(summary, ensure_ascii=False), flush=True)
raise SystemExit(0 if result["all_pass"] else 1)
