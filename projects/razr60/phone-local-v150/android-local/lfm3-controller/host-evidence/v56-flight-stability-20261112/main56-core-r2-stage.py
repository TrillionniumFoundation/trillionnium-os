#!/usr/bin/env python3
"""Run the unchanged original core101 on the exact two-repair Main56 successor.
The actual56r1 failed receipt and all595 original source files remain immutable.
Only the reviewed Shopping evidence conversion and finalization fixture are
materialized in a new root. Original101 order, nested18, compiler strictness and
owned-child cleanup are unchanged. No Android build, signing or phone action.
"""
import gzip,hashlib,json,os,re,shutil,signal,stat,subprocess,sys,time,traceback
from pathlib import Path,PurePosixPath

CONFIG=json.loads("{\"schema\":\"hepta.main56-core101-coordinator-config.v1\",\"root\":\"/home/alex/hepta-local-007f-20261111/v56-main-core101-materialized-host-r2\",\"source_root\":\"/home/alex/hepta-local-007f-20261111/v56-main-core101-materialized-host-r2/source\",\"prior_root\":\"/home/alex/hepta-local-007f-20261111/v56-main-core101-materialized-host-r1\",\"prior_source_commit\":\"dd2cd48054c2c6f0b2597b7d9be05edd8ce6b34e\",\"prior_source_file_count\":595,\"prior_aggregate\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v56-main-core101-materialized-host-r1/AGGREGATE.json\",\"bytes\":1416544,\"sha256\":\"38baa995ee76520e1a9ff7a14baf51afdbd4f1af53f747ce7a0d114ef4809c90\",\"git_blob_sha\":\"660335b7f19f519af4cfd168ebee186f1a4693b9\"},\"aggregate\":{\"bytes\":1427055,\"sha256\":\"c1cc7cc16eef4c3a34131ee719101a69db080b76e72c98f03248036fc6fd628f\",\"git_blob_sha\":\"0803dec4b6acc359b810bb79ca6fdd01ada69a8c\"},\"delta\":{\"bytes\":58425,\"sha256\":\"f39e868cc4ec10526a242c26bcade6a7928e501944dfe5ab73e395b1247d87c1\",\"git_blob_sha\":\"9150a118ef3bc92b75fdbcef559f801ceafbab1a\"},\"inventory\":{\"bytes\":103795,\"sha256\":\"ca24673843908c7f9343c949af64b8393e69ce53605128782036ae9ce9d1f46e\",\"git_blob_sha\":\"c43a4be934ca00942ceeed086e16fc4b81d3a519\"},\"source_blob_map\":{\"bytes\":141875,\"sha256\":\"8d8cf9767861029b1cd4c6bb1143e07ee92296a475a44ae1979db79756233926\",\"git_blob_sha\":\"07cc1ccced2c41df1fcb06e5195650362b3676c0\"},\"compiler_inputs\":{\"bytes\":34376,\"sha256\":\"2b9e1d971a60d09df7303f050cef40d4b254b016a6f68c272035ec11ef854071\",\"git_blob_sha\":\"b5d627b7d692732689d337007816b8635b961933\"},\"source_file_count\":595,\"compiler_input_count\":217,\"java_source_count\":115,\"host_input_count\":419,\"expected_host_inputs\":{\"bytes\":64953,\"sha256\":\"5dc065ab22aa7d05b62bb3b323ea2b180b89492ec2833b6a3dbfbca0442f48db\",\"git_blob_sha\":\"ccff0865313d07728807b6546605cb6bb4e00263\"},\"prior_inventory\":{\"bytes\":103795,\"sha256\":\"4581b1c7cfe27caf4e3d24562072baa511705f3e13205fc8720021bba9cc4512\",\"git_blob_sha\":\"89e9aaec004f6b07a7b60b24d9e1fba397e924cc\"},\"prior_compiler_inputs\":{\"bytes\":34376,\"sha256\":\"71c6e4c9f0eaaf9abbfffa54dc7ce778deaacd04e4d9e911d763184673de2259\",\"git_blob_sha\":\"63eca692ebe619159d3a0f74d4a19b47e08daf8d\"},\"prior_source_blob_map\":{\"bytes\":141875,\"sha256\":\"78c2a62a2ec78e83c3e634cf102f1971e14035078b378bf9c1d38da2a8cea6ab\",\"git_blob_sha\":\"9c897ff1cd3a89f5bb0a3aae91b1b60d69934160\"},\"prior_core_result\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v56-main-core101-materialized-host-r1/RESULT.json\",\"git_blob_sha\":\"3274c9f9254450635364967eb3701ad30056910c\",\"bytes\":8174,\"sha256\":\"df5c72a750e8ffc51fcb798565849157a9fbdfd2386314c305782cf7c96d2dc5\"},\"prior_core_source\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v56-main-core101-materialized-host-r1/stage.py\",\"git_blob_sha\":\"c7fb116535bccafcf91261e787255ac5a446b5ec\",\"bytes\":191795,\"sha256\":\"613022769d3492365f138de2858501174bf77b2f3b9b60e907058ff2b4794756\"},\"prior_host_checks\":{\"bytes\":86558,\"sha256\":\"4c1a27164202fc8a1dc1326aafa6891c3967964a0f97f1cc7c8476f9680ddf21\"},\"prior_signed_result\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-main-sign-r1/RESULT.json\",\"git_blob_sha\":\"7c7b5b8157c5212609b2a5faab68015928721dae\",\"bytes\":31662,\"sha256\":\"3caa0d8ae5252352fb606db1d851fd9e960423c0f7374a76c58b89c688556535\"},\"runner\":{\"path\":\"tools/run_host_checks.py\",\"bytes\":13537,\"sha256\":\"dc64aa551a0eddd6429ad3340db5445e9c00403a2110b48e1c05662f5d46ec3a\",\"git_blob_sha\":\"616bd114db54c27c9066d7451185123a5c5b9f17\"},\"build_identity\":{\"bytes\":2970,\"sha256\":\"7d5ad2641e9a3635fd04aa47ce3ea50a1a4f16b883a98b2ab407878eef36f6e6\",\"git_blob_sha\":\"393b3133c988a422f53a37ecb6052e60d508bf2e\"},\"jdk\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64\",\"java\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/java\",\"bytes\":14544,\"sha256\":\"bb70208200cb6538b877d80478141194a716edb591f4910ec106589291e99196\"},\"javac\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/javac\",\"bytes\":14592,\"sha256\":\"2aaf03d13aeb80b8269696f2dcd9f4937d7366bbc68f91fdc703cf157e8f39c4\"},\"cc_sha256\":\"b5f1b773a7c733738352000c92a077dc5852a1a2fc6d836b1e411be1e9ec5f88\",\"timeout_seconds\":900,\"expected_top_level_checks\":101,\"nested_completion_stages\":[\"compile\",\"actual-completion\",\"notes-task-phase\",\"notes-task-phase-grammar\",\"notes-list-provenance\",\"notes-recovery\",\"notes-recovery-grammar\",\"notes-task-scope\",\"notes-task-scope-grammar\",\"calculator-input\",\"calculator-input-grammar\",\"failed-action-observation\",\"notes-editor-phase\",\"notes-editor-phase-grammar\",\"completion-status\",\"completion-status-grammar\",\"notes-create-workflow\",\"notes-workflow-controller\"],\"key\":\"007f-v56-main-core101-materialized-host-r2\",\"source_materialized_here\":true,\"unsigned_build_prerequisite_required\":false,\"changed_existing_paths\":[\"src/org/trillionnium/hepta/local/WebShoppingDomain.java\",\"tests/warm-finalization/prepare_fixture.py\"],\"new_paths\":[],\"unchanged_prior_source_rows\":593,\"prior_failed_runs_are_preserved_history\":true,\"actual_flight_results_provider_ready\":false,\"prior_failed_stdout\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v56-main-core101-materialized-host-r1/host-checks/background-client.stdout\",\"bytes\":1567,\"sha256\":\"0fc8f7fb1d2ef48d95903068d5da303dc80d37f9f07c7f4999acc3f314d2ee67\",\"git_blob_sha\":\"7367b41bc7fe35f428fe40698c21da30b0c50284\"},\"historical55_inventory\":{\"bytes\":103607,\"sha256\":\"65bf7934d82692f45c10aedb947613043453b30bc7d55c4dc8b7e44e4ca0bed1\"},\"historical55_host_checks\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-main-core101-materialized-host-r3/host-checks/HOST-CHECKS.json\",\"bytes\":101418,\"sha256\":\"3b38bc5ca5cb1474c165c83c72ba41cbeea20543838674b0be72735cd7c23f1f\"}}")
DELTA_RAW="{\n  \"schema\": \"hepta.main56-r1-failure-repair-aggregate-exact-delta.v1\",\n  \"status\": \"source-only; exact successor to actually materialized Core56 r1 source\",\n  \"base_aggregate\": {\n    \"bytes\": 1416544,\n    \"sha256\": \"38baa995ee76520e1a9ff7a14baf51afdbd4f1af53f747ce7a0d114ef4809c90\",\n    \"git_blob_sha\": \"660335b7f19f519af4cfd168ebee186f1a4693b9\"\n  },\n  \"result_aggregate\": {\n    \"bytes\": 1427055,\n    \"sha256\": \"c1cc7cc16eef4c3a34131ee719101a69db080b76e72c98f03248036fc6fd628f\",\n    \"git_blob_sha\": \"0803dec4b6acc359b810bb79ca6fdd01ada69a8c\"\n  },\n  \"files\": [\n    {\n      \"path\": \"src/org/trillionnium/hepta/local/WebShoppingDomain.java\",\n      \"base_actual_source\": {\n        \"bytes\": 31708,\n        \"sha256\": \"c1c564118915d230d2b5c9ff275c05263b9253e3c876d03db7b63a5a76248aa0\",\n        \"git_blob_sha\": \"da3880029d43376cd271df68517675615c2800bd\"\n      },\n      \"base_overlay_present\": true,\n      \"base_raw_utf8\": \"package org.trillionnium.hepta.local;\\n\\nimport org.json.JSONObject;\\nimport org.trillionnium.hepta.local.web.WebShoppingGoal;\\nimport org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;\\nimport org.trillionnium.hepta.webprotocol.WebEvidenceBinding;\\nimport org.trillionnium.hepta.webprotocol.WebSitePolicy;\\nimport java.util.ArrayList;\\nimport java.util.Arrays;\\nimport java.util.Collections;\\nimport java.util.HashSet;\\nimport java.util.LinkedHashMap;\\nimport java.util.List;\\nimport java.util.Map;\\nimport java.util.Set;\\n\\n/**\\n * A same-frame official-shopping capability restriction. It does not dispatch.\\n * Targets are real native AX IDs with the actual card text/ancestry/geometry bridge.\\n * Full before/after raw hashes bind ARM; stable region semantics bind the model action page key.\\n * Source/currency/price data never originate in a model answer or search snippet.\\n */\\nfinal class WebShoppingDomain {\\n    static final String SCHEMA=\\\"hepta.mi-current-action-domain.v2\\\";\\n    final String taskId,ownerSha,contractSha,authorizationSha,observationId,stateSha,generation,bindingSha;\\n    final String instance,url,phase,pageKey;\\n    final int displayId,windowId;\\n    final long epoch,captureStarted,captureEnded;\\n    final Set<String> clickIds;\\n    private final Map<String,MiPublicProductPage.Link> links;\\n    private final Map<String,Object> proof;\\n    private final MiPublicProductPage page;\\n    private final boolean localPriceVerified;\\n    private final Navigation navigation;\\n    private final String sourceCaptureRaw,observedArmRaw;\\n    private final WebRegionNativeBridge regionBridge;\\n\\n    private WebShoppingDomain(String task,WebShoppingGoal goal,TaskAuthorization.Gate auth,PhoneObservation frame,\\n            WebEvidenceReceipt receipt,String binding,String phase,String key,\\n            Map<String,MiPublicProductPage.Link> links,MiPublicProductPage page,boolean priceVerified,\\n            Navigation navigation,Map<String,Object> proof,String sourceCaptureRaw,WebRegionNativeBridge regionBridge){\\n        taskId=task;ownerSha=goal.ownerSha256;contractSha=goal.contractSha256;authorizationSha=auth.authorization.sha256;\\n        observationId=frame.id;stateSha=frame.treeSha256;generation=frame.backgroundGeneration;bindingSha=binding;\\n        instance=receipt.instance;url=receipt.url;epoch=receipt.epoch;displayId=receipt.displayId;windowId=receipt.windowId;\\n        captureStarted=receipt.started;captureEnded=receipt.ended;this.phase=phase;pageKey=key;\\n        this.links=Collections.unmodifiableMap(new LinkedHashMap<String,MiPublicProductPage.Link>(links));\\n        clickIds=Collections.unmodifiableSet(new HashSet<String>(links.keySet()));this.page=page;\\n        localPriceVerified=priceVerified;this.navigation=navigation;this.sourceCaptureRaw=sourceCaptureRaw;\\n        this.regionBridge=regionBridge;this.observedArmRaw=null;\\n        this.proof=Collections.unmodifiableMap(new LinkedHashMap<String,Object>(proof));\\n    }\\n    private WebShoppingDomain(WebShoppingDomain original,Navigation navigation){\\n        this(original,navigation,original.observedArmRaw);\\n    }\\n    private WebShoppingDomain(WebShoppingDomain original,Navigation navigation,String armRaw){\\n        taskId=original.taskId;ownerSha=original.ownerSha;contractSha=original.contractSha;authorizationSha=original.authorizationSha;\\n        observationId=original.observationId;stateSha=original.stateSha;generation=original.generation;bindingSha=original.bindingSha;\\n        instance=original.instance;url=original.url;epoch=original.epoch;displayId=original.displayId;windowId=original.windowId;\\n        captureStarted=original.captureStarted;captureEnded=original.captureEnded;phase=original.phase;pageKey=original.pageKey;\\n        links=original.links;clickIds=original.clickIds;page=original.page;localPriceVerified=original.localPriceVerified;\\n        sourceCaptureRaw=original.sourceCaptureRaw;regionBridge=original.regionBridge;observedArmRaw=armRaw;\\n        this.navigation=navigation;Map<String,Object> out=new LinkedHashMap<String,Object>(original.proof);\\n        if(navigation!=null){\\n            out.put(\\\"model_navigation\\\",navigation.evidence());out.put(\\\"model_navigation_confirmed\\\",true);\\n            out.put(\\\"result_ready_for_completion_gate\\\",localPriceVerified);\\n        }\\n        if(armRaw!=null){out.put(\\\"observed_link_arm_json_utf8\\\",armRaw);out.put(\\\"observed_link_armed\\\",true);}\\n        proof=Collections.unmodifiableMap(out);\\n    }\\n    static WebShoppingDomain observed(String task,WebShoppingGoal goal,TaskAuthorization.Gate auth,PhoneObservation frame,\\n                                      WebEvidenceReceipt receipt,JSONObject immutableBinding)throws Exception{\\n        String binding=common(task,goal,auth,frame,receipt,immutableBinding);\\n        need(\\\"captured\\\".equals(receipt.status),\\\"actual captured page required\\\");\\n        JSONObject dom=receipt.dom(),capture=receipt.capture();WebSitePolicy policy=WebSitePolicy.forShopping(goal);\\n        MiPublicProductPage page=MiPublicProductPage.read(goal,policy,receipt.url,dom);\\n        WebNativeGeometry geometry=WebNativeGeometry.read(capture,dom,receipt.displayId,receipt.windowId,receipt.stability());\\n        WebRegionNativeBridge nativeBridge=null;\\n        Map<String,MiPublicProductPage.Link> targets=new LinkedHashMap<String,MiPublicProductPage.Link>();\\n        List<Map<String,Object>> capabilities=new ArrayList<Map<String,Object>>();\\n        Map<String,Object> proof=base(task,goal,auth,frame,receipt,binding);\\n        proof.put(\\\"page\\\",page.evidence());proof.put(\\\"site_policy\\\",jsonMap(policy.evidence()));\\n        proof.put(\\\"site_policy_sha256\\\",policy.sha256);proof.put(\\\"native_geometry\\\",geometry==null?null:geometry.evidence());\\n        if(geometry!=null&&!page.modalPresent&&page.productLinks.size()==1\\n                &&\\\"official_public_search\\\".equals(page.phase)){\\n            MiPublicProductPage.Link link=page.productLinks.get(0);\\n            nativeBridge=WebRegionNativeBridge.bind(frame,receipt);\\n            if(nativeBridge!=null&&receipt.stability()!=null&&receipt.stability().region!=null\\n                    &&nativeBridge.anchorDomPath.equals(link.path)\\n                    &&nativeBridge.regionRoot.equals(receipt.stability().region.rootPath)\\n                    &&receipt.stability().permitsActionTargetPath(link.path)){\\n                PhoneObservation.Node node=nativeBridge.anchor;\\n                targets.put(node.id,link);Map<String,Object> cap=nodeEvidence(node);\\n                cap.put(\\\"purpose\\\",\\\"open_observed_official_product_detail\\\");cap.put(\\\"observed_link\\\",link.evidence());\\n                cap.put(\\\"target_source\\\",\\\"same_frame_native_accessibility_node_id\\\");\\n                cap.put(\\\"native_region_bridge\\\",jsonMap(nativeBridge.evidence()));\\n                cap.put(\\\"css_rect_used_as_target\\\",false);capabilities.add(cap);\\n            }else nativeBridge=null;\\n        }\\n        boolean localPrice=false;\\n        Map<String,Object> visible=new LinkedHashMap<String,Object>();\\n        if(geometry!=null&&!page.modalPresent&&page.detail!=null&&page.detail.exactPublicPrice\\n                &&!goal.singleUnitRequested&&!goal.specificationsRequested){\\n            MiPublicProductPage.Detail detail=page.detail;\\n            PhoneObservation.Node model=uniqueReadable(frame,geometry,detail.modelLabel);\\n            PhoneObservation.Node amount=uniqueReadable(frame,geometry,detail.priceRaw);\\n            PhoneObservation.Node currency=uniqueReadable(frame,geometry,detail.currencyRaw);\\n            if(model!=null&&amount!=null&&currency!=null&&model!=amount&&model!=currency&&amount!=currency){\\n                localPrice=true;visible.put(\\\"model\\\",nodeEvidence(model));visible.put(\\\"price\\\",nodeEvidence(amount));\\n                visible.put(\\\"currency\\\",nodeEvidence(currency));\\n            }\\n        }\\n        proof.put(\\\"phase\\\",page.phase);proof.put(\\\"native_ax_capabilities\\\",capabilities);\\n        proof.put(\\\"allowed_click_ids\\\",new ArrayList<String>(targets.keySet()));\\n        proof.put(\\\"actual_product_native_readback\\\",visible);proof.put(\\\"same_frame_public_price_observed\\\",localPrice);\\n        proof.put(\\\"model_navigation_confirmed\\\",false);proof.put(\\\"model_navigation\\\",null);\\n        proof.put(\\\"observed_link_armed\\\",false);proof.put(\\\"observed_link_arm_json_utf8\\\",null);\\n        proof.put(\\\"result_ready_for_completion_gate\\\",false);\\n        proof.put(\\\"missing\\\",new ArrayList<String>(page.missing));\\n        proof.put(\\\"next_goal\\\",!targets.isEmpty()?\\\"打开同帧实际 AX3000T 官方商品链接；不要点击购买、登录、领券或购物车。\\\":\\n                localPrice?\\\"已观察到商品公开价；仍须同任务原生模型导航因果链及最终清理门。\\\":\\n                \\\"当前页面缺少可验证的公开商品控件或价格；只能等待或报告未完成，不能猜测SKU、价格、币种。\\\");\\n        JSONObject semantic=new JSONObject().put(\\\"native_url\\\",receipt.url).put(\\\"instance\\\",receipt.instance)\\n                .put(\\\"epoch\\\",receipt.epoch).put(\\\"policy_sha256\\\",policy.sha256)\\n                .put(\\\"native_geometry_sha256\\\",geometry==null?JSONObject.NULL:geometry.fingerprint)\\n                .put(\\\"allowed_click_ids\\\",new org.json.JSONArray(targets.keySet()))\\n                .put(\\\"native_region_semantic_sha256\\\",nativeBridge==null?JSONObject.NULL:nativeBridge.semanticFingerprint)\\n                .put(\\\"selected_region_sha256\\\",receipt.stability()==null||receipt.stability().region==null?JSONObject.NULL:receipt.stability().region.fullRegionSha256)\\n                .put(\\\"selected_region_ancestor_sha256\\\",receipt.stability()==null||receipt.stability().region==null?JSONObject.NULL:receipt.stability().region.ancestorSha256)\\n                .put(\\\"page\\\",new JSONObject(page.evidence()));\\n        return new WebShoppingDomain(task,goal,auth,frame,receipt,binding,page.phase,WebEvidenceJson.sha(semantic.toString()),\\n                targets,page,localPrice,null,proof,capture.toString(),nativeBridge);\\n    }\\n    static WebShoppingDomain waiting(String task,WebShoppingGoal goal,TaskAuthorization.Gate auth,PhoneObservation frame,\\n                                    WebEvidenceReceipt receipt,JSONObject immutableBinding)throws Exception{\\n        String binding=common(task,goal,auth,frame,receipt,immutableBinding);\\n        need((\\\"unavailable\\\".equals(receipt.status)||\\\"state_changed\\\".equals(receipt.status))&&!receipt.cleanupKnown,\\n                \\\"only authenticated metadata-only capture wait\\\");\\n        Map<String,Object> proof=base(task,goal,auth,frame,receipt,binding);proof.put(\\\"phase\\\",\\\"official_page_capture_pending\\\");\\n        proof.put(\\\"capture_callback\\\",jsonMap(receipt.callback()));proof.put(\\\"allowed_click_ids\\\",Collections.emptyList());\\n        proof.put(\\\"native_ax_capabilities\\\",Collections.emptyList());proof.put(\\\"same_frame_public_price_observed\\\",false);\\n        proof.put(\\\"model_navigation_confirmed\\\",false);proof.put(\\\"result_ready_for_completion_gate\\\",false);\\n        proof.put(\\\"next_goal\\\",\\\"网页原始证据尚未稳定；只能等待或报告未完成。\\\");\\n        return new WebShoppingDomain(task,goal,auth,frame,receipt,binding,\\\"official_page_capture_pending\\\",\\n                WebEvidenceJson.sha(receipt.callback().toString()+\\\"\\\\n\\\"+frame.id),\\n                Collections.<String,MiPublicProductPage.Link>emptyMap(),null,false,null,proof,null,null);\\n    }\\n    private static String common(String task,WebShoppingGoal goal,TaskAuthorization.Gate auth,PhoneObservation frame,\\n                               WebEvidenceReceipt receipt,JSONObject immutableBinding)throws Exception{\\n        need(goal!=null&&auth!=null&&receipt!=null&&task.equals(auth.taskId)&&goal.ownerSha256.equals(auth.authorization.instructionSha256)\\n                &&WebShoppingGoal.TOOL_CEILING.containsAll(auth.authorization.allowedTools),\\\"same original bounded shopping authorization\\\");\\n        need(WebEvidenceProtocol.HELPER_VERSION_CODE==6\\n                &&\\\"hepta.web-helper.binding.v4\\\".equals(WebEvidenceProtocol.BINDING_SCHEMA)\\n                &&\\\"org.trillionnium.hepta.webhelper.IWebEvidence.v4\\\".equals(WebEvidenceProtocol.DESCRIPTOR),\\n                \\\"shopping requires explicit code6/v4 peer and independently replayed scoped capture\\\");\\n        WebSitePolicy policy=WebSitePolicy.forShopping(goal);\\n        need(immutableBinding!=null&&WebEvidenceProtocol.BINDING_SCHEMA.equals(immutableBinding.get(\\\"schema\\\"))\\n                &&task.equals(immutableBinding.get(\\\"task_id\\\"))&&goal.owner.equals(immutableBinding.get(\\\"owner\\\"))\\n                &&goal.ownerSha256.equals(immutableBinding.get(\\\"owner_sha256\\\"))&&goal.contractSha256.equals(immutableBinding.get(\\\"contract_sha256\\\"))\\n                &&WebShoppingGoal.KIND.equals(immutableBinding.get(\\\"goal_kind\\\"))\\n                &&policy.id.equals(immutableBinding.get(\\\"site_policy_id\\\"))&&policy.sha256.equals(immutableBinding.get(\\\"site_policy_sha256\\\"))\\n                &&policy.initialUrl.equals(immutableBinding.get(\\\"initial_url\\\"))\\n                &&auth.authorization.sha256.equals(immutableBinding.getJSONObject(\\\"authorization\\\").get(\\\"authorization_sha256\\\"))\\n                &&WebEvidenceJson.number(immutableBinding.getJSONObject(\\\"helper_identity\\\"),\\\"version_code\\\")==6,\\n                \\\"exact per-lease shopping contract/site/authority binding required\\\");\\n        String binding=WebEvidenceBinding.sha256(immutableBinding);\\n        need(frame!=null&&!frame.nodesTruncated&&WebEvidenceProtocol.HELPER_PACKAGE.equals(frame.packageName)\\n                &&frame.windowMetadata!=null&&\\\"observed\\\".equals(frame.windowMetadata.status)\\n                &&Integer.valueOf(1).equals(frame.windowMetadata.type)&&frame.windowMetadata.displayId!=null\\n                &&frame.windowMetadata.displayId==receipt.displayId&&frame.windowId==receipt.windowId\\n                &&receipt.displayId>0&&frame.backgroundGeneration!=null&&binding.equals(receipt.bindingSha)\\n                &&WebEvidenceJson.number(immutableBinding.getJSONObject(\\\"background\\\"),\\\"display_id\\\")==receipt.displayId\\n                &&frame.backgroundGeneration.equals(immutableBinding.getJSONObject(\\\"background\\\").get(\\\"generation\\\")),\\n                \\\"same current owned AX/DOM application window required\\\");\\n        return binding;\\n    }\\n    private static Map<String,Object> base(String task,WebShoppingGoal goal,TaskAuthorization.Gate auth,PhoneObservation frame,\\n                                           WebEvidenceReceipt receipt,String binding){\\n        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put(\\\"schema\\\",SCHEMA);out.put(\\\"task_id\\\",task);\\n        out.put(\\\"owner_sha256\\\",goal.ownerSha256);out.put(\\\"contract_sha256\\\",goal.contractSha256);out.put(\\\"authorization_sha256\\\",auth.authorization.sha256);\\n        out.put(\\\"observation_id\\\",frame.id);out.put(\\\"observation_state_sha256\\\",frame.treeSha256);out.put(\\\"app_tree_sha256\\\",frame.state.appTreeSha256);\\n        out.put(\\\"binding_sha256\\\",binding);out.put(\\\"webview_instance\\\",receipt.instance);out.put(\\\"navigation_epoch\\\",receipt.epoch);\\n        out.put(\\\"display_id\\\",receipt.displayId);out.put(\\\"window_id\\\",receipt.windowId);out.put(\\\"background_generation\\\",frame.backgroundGeneration);\\n        out.put(\\\"current_native_url\\\",receipt.url);out.put(\\\"dom_sha256\\\",receipt.domSha);out.put(\\\"business_verified\\\",false);\\n        out.put(\\\"grants_tool_authority\\\",false);out.put(\\\"bootstrap_search_is_model_query\\\",false);\\n        out.put(\\\"css_to_screen_mapping_used\\\",false);out.put(\\\"dom_layout_visibility_is_screen_proof\\\",false);\\n        out.put(\\\"final_native_and_cleanup_gates_verified\\\",false);return out;\\n    }\\n    String observedLinkAnchorPath(ActionDecision action){\\n        requireCurrent(action);need(\\\"click\\\".equals(action.action)&&links.containsKey(action.nodeId),\\\"current product click required\\\");\\n        return links.get(action.nodeId).path;\\n    }\\n    WebShoppingDomain withObservedLinkArm(JSONObject actualArm)throws Exception{\\n        need(observedArmRaw==null&&sourceCaptureRaw!=null&&regionBridge!=null&&clickIds.size()==1,\\n                \\\"single actual fresh product region can accept one ARM\\\");\\n        JSONObject source=new JSONObject(sourceCaptureRaw);\\n        org.trillionnium.hepta.webprotocol.WebDomStability.Result stable=\\n                org.trillionnium.hepta.webprotocol.WebDomStability.verify(source.getString(\\\"before_dom_raw_utf8\\\"),\\n                        source.getString(\\\"dom_raw_utf8\\\"),WebSitePolicy.ID,source.getJSONObject(\\\"dom_stability\\\"));\\n        need(org.trillionnium.hepta.webprotocol.WebObservedNavigation.ARM_SCHEMA.equals(actualArm.get(\\\"schema\\\"))\\n                &&taskId.equals(actualArm.get(\\\"task_id\\\"))&&bindingSha.equals(actualArm.get(\\\"binding_sha256\\\"))\\n                &&instance.equals(actualArm.get(\\\"webview_instance\\\"))&&epoch==WebEvidenceJson.number(actualArm,\\\"navigation_epoch\\\")\\n                &&displayId==WebEvidenceJson.number(actualArm,\\\"display_id\\\")&&windowId==WebEvidenceJson.number(actualArm,\\\"actual_window_id\\\")\\n                &&source.get(\\\"challenge\\\").equals(actualArm.get(\\\"source_capture_challenge\\\"))\\n                &&source.get(\\\"dom_sha256\\\").equals(actualArm.get(\\\"source_dom_sha256\\\"))\\n                &&source.get(\\\"before_dom_sha256\\\").equals(actualArm.get(\\\"source_before_dom_sha256\\\"))\\n                &&source.get(\\\"dom_stability_sha256\\\").equals(actualArm.get(\\\"source_stability_sha256\\\"))\\n                &&stable.region!=null&&regionBridge.anchorDomPath.equals(actualArm.get(\\\"anchor_dom_path\\\"))\\n                &&stable.region.fullRegionSha256.equals(actualArm.get(\\\"region_sha256\\\"))\\n                &&stable.region.hrefResolved.equals(actualArm.get(\\\"observed_href_resolved\\\"))\\n                &&Boolean.FALSE.equals(actualArm.get(\\\"native_click_observed\\\"))\\n                &&Boolean.FALSE.equals(actualArm.get(\\\"navigation_dispatched\\\"))\\n                &&Boolean.FALSE.equals(actualArm.get(\\\"transaction_authority\\\"))\\n                &&Boolean.FALSE.equals(actualArm.get(\\\"business_verified\\\")),\\n                \\\"ARM must describe this exact last successful capture and unique native target\\\");\\n        // The Client has already replayed the original request with verifyArm.\\n        // This setter preserves its exact typed record; it creates no request or outcome.\\n        return new WebShoppingDomain(this,navigation,org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(actualArm));\\n    }\\n    WebShoppingDomain withNavigation(Navigation proof){\\n        need(proof!=null&&proof.matches(this),\\\"navigation belongs to another task/product/page\\\");\\n        return new WebShoppingDomain(this,proof);\\n    }\\n    boolean resultReady(){return localPriceVerified&&navigation!=null&&navigation.matches(this);}\\n    Map<String,Object> resultRecord(){\\n        need(resultReady()&&page!=null&&page.detail!=null,\\\"actual same-product result and navigation missing\\\");\\n        Map<String,Object> out=new LinkedHashMap<String,Object>(page.detail.evidence());\\n        out.put(\\\"committed_url\\\",url);out.put(\\\"task_id\\\",taskId);out.put(\\\"owner_sha256\\\",ownerSha);out.put(\\\"contract_sha256\\\",contractSha);\\n        out.put(\\\"observation_id\\\",observationId);out.put(\\\"observation_state_sha256\\\",stateSha);out.put(\\\"binding_sha256\\\",bindingSha);\\n        out.put(\\\"webview_instance\\\",instance);out.put(\\\"navigation_epoch\\\",epoch);out.put(\\\"display_id\\\",displayId);out.put(\\\"window_id\\\",windowId);\\n        out.put(\\\"model_navigation\\\",navigation.evidence());out.put(\\\"same_frame_native_labels_verified\\\",true);\\n        out.put(\\\"exact_configuration_verified\\\",false);out.put(\\\"price_scope\\\",\\\"displayed_public_product_page_price\\\");\\n        out.put(\\\"business_verified\\\",false);out.put(\\\"final_native_and_cleanup_gates_verified\\\",false);return out;\\n    }\\n    Map<String,Object> evidence(){return new LinkedHashMap<String,Object>(proof);}\\n    Set<String> clicks(Set<String> original){Set<String> out=new HashSet<String>(original);out.retainAll(clickIds);return out;}\\n    Set<String> edits(Set<String> original){return Collections.emptySet();}\\n    Set<String> openPackages(Set<String> original){return Collections.emptySet();}\\n    <T> Map<String,T> noNodeActions(Map<String,T> original){return Collections.emptyMap();}\\n    Set<String> toolMask(Set<String> original){\\n        Set<String> out=new HashSet<String>(Arrays.asList(\\\"wait\\\",\\\"done\\\"));if(!clickIds.isEmpty())out.add(\\\"click\\\");\\n        if(original!=null)out.retainAll(original);return out;\\n    }\\n    void requireCurrent(ActionDecision action){\\n        need(action!=null&&observationId.equals(action.observationId)&&WebEvidenceProtocol.HELPER_PACKAGE.equals(action.packageName),\\n                \\\"shopping action belongs to another current frame\\\");\\n        if(\\\"wait\\\".equals(action.action))return;\\n        if(\\\"done\\\".equals(action.action)){need(!\\\"success\\\".equals(action.status)||resultReady(),\\\"actual product result not yet independently ready\\\");return;}\\n        if(\\\"click\\\".equals(action.action)){need(action.nodeId!=null&&clickIds.contains(action.nodeId),\\\"only current exact official product link is allowed\\\");return;}\\n        throw new IllegalArgumentException(\\\"该商品页面没有已证明的只读操作；禁止购物、输入、提交或跨站操作\\\");\\n    }\\n    static final class Navigation {\\n        private final String task,owner,contract,authorization,binding,generation,instance,url,run,beforeObservation,afterObservation;\\n        private final int display,window;private final long targetEpoch,dispatchBefore,dispatchAfter;\\n        private final Map<String,Object> evidence;\\n        private Navigation(WebShoppingDomain before,WebShoppingDomain after,String modelRun,long start,long end,ActionDecision action,Map<String,Object> helperNavigation){\\n            task=before.taskId;owner=before.ownerSha;contract=before.contractSha;authorization=before.authorizationSha;\\n            binding=before.bindingSha;generation=before.generation;instance=before.instance;url=after.url;\\n            display=before.displayId;window=before.windowId;targetEpoch=after.epoch;run=modelRun;\\n            beforeObservation=before.observationId;afterObservation=after.observationId;dispatchBefore=start;dispatchAfter=end;\\n            Map<String,Object> out=new LinkedHashMap<String,Object>();out.put(\\\"schema\\\",\\\"hepta.mi-model-navigation.v1\\\");\\n            out.put(\\\"task_id\\\",task);out.put(\\\"owner_sha256\\\",owner);out.put(\\\"contract_sha256\\\",contract);out.put(\\\"authorization_sha256\\\",authorization);\\n            out.put(\\\"binding_sha256\\\",binding);out.put(\\\"background_generation\\\",generation);out.put(\\\"webview_instance\\\",instance);\\n            out.put(\\\"display_id\\\",display);out.put(\\\"window_id\\\",window);out.put(\\\"model_run_id\\\",run);out.put(\\\"action\\\",\\\"click\\\");out.put(\\\"node_id\\\",action.nodeId);\\n            out.put(\\\"before_observation_id\\\",beforeObservation);out.put(\\\"after_observation_id\\\",afterObservation);\\n            out.put(\\\"source_url\\\",before.url);out.put(\\\"target_url\\\",url);out.put(\\\"source_epoch\\\",before.epoch);out.put(\\\"target_epoch\\\",targetEpoch);\\n            out.put(\\\"dispatch_before_elapsed_ms\\\",start);out.put(\\\"dispatch_after_elapsed_ms\\\",end);\\n            out.put(\\\"actual_source_link\\\",before.links.get(action.nodeId).evidence());out.put(\\\"accepted\\\",true);out.put(\\\"dispatched\\\",true);out.put(\\\"stale\\\",false);\\n            out.put(\\\"model_issued\\\",true);out.put(\\\"observed_link_arm_json_utf8\\\",before.observedArmRaw);\\n            out.put(\\\"helper_navigation_verdict\\\",helperNavigation);out.put(\\\"business_verified\\\",false);evidence=Collections.unmodifiableMap(out);\\n        }\\n        /**\\n         * Called only from the real controller's accepted native-model action +\\n         * actual executor Outcome. The clocks bracket that original dispatch.\\n         * Planned/unknown/stale clicks and operator navigation cannot mint this object.\\n         */\\n        static Navigation confirm(WebShoppingDomain before,WebShoppingDomain after,ActionDecision action,String nativeModelRunId,\\n                                  boolean accepted,boolean dispatched,boolean stale,long dispatchBefore,long dispatchAfter){\\n            need(before!=null&&after!=null&&action!=null&&accepted&&dispatched&&!stale\\n                    &&nativeModelRunId!=null&&nativeModelRunId.matches(\\\"[0-9a-f]{32}\\\"),\\\"actual accepted model dispatch required\\\");\\n            before.requireCurrent(action);need(\\\"click\\\".equals(action.action)&&before.links.containsKey(action.nodeId),\\\"real product link click required\\\");\\n            need(\\\"official_public_search\\\".equals(before.phase)&&\\\"official_product_detail\\\".equals(after.phase)\\n                    &&before.taskId.equals(after.taskId)&&before.ownerSha.equals(after.ownerSha)&&before.contractSha.equals(after.contractSha)\\n                    &&before.authorizationSha.equals(after.authorizationSha)&&before.bindingSha.equals(after.bindingSha)\\n                    &&before.generation.equals(after.generation)&&before.instance.equals(after.instance)\\n                    &&before.displayId==after.displayId&&before.windowId==after.windowId\\n                    &&before.links.get(action.nodeId).hrefResolved.equals(after.url)&&after.epoch>before.epoch,\\n                    \\\"actual same-lease detail navigation does not match the observed source link\\\");\\n            need(before.captureEnded>=0&&before.captureEnded<=dispatchBefore&&dispatchBefore<=dispatchAfter\\n                    &&dispatchAfter<=after.captureStarted,\\\"actual monotonic dispatch/capture order required\\\");\\n            try{\\n                need(before.observedArmRaw!=null&&after.sourceCaptureRaw!=null,\\\"actual ARM and destination capture required\\\");\\n                JSONObject arm=new JSONObject(before.observedArmRaw),destination=new JSONObject(after.sourceCaptureRaw);\\n                need(nativeModelRunId.equals(arm.get(\\\"model_run_id\\\"))\\n                        &&before.links.get(action.nodeId).path.equals(arm.get(\\\"anchor_dom_path\\\")),\\\"ARM belongs to another actual model action\\\");\\n                Object rawNavigation=destination.get(\\\"observed_link_navigation\\\");\\n                need(rawNavigation instanceof JSONObject,\\\"actual helper navigation event absent or incomplete\\\");\\n                JSONObject verdict=org.trillionnium.hepta.webprotocol.WebObservedNavigation.verifyNavigation(\\n                        arm,(JSONObject)rawNavigation,destination,dispatchBefore,dispatchAfter);\\n                return new Navigation(before,after,nativeModelRunId,dispatchBefore,dispatchAfter,action,jsonMap(verdict));\\n            }catch(Exception invalid){\\n                throw new IllegalArgumentException(\\\"actual typed same-lease link navigation not verified\\\",invalid);\\n            }\\n        }\\n        boolean matches(WebShoppingDomain now){\\n            return now!=null&&task.equals(now.taskId)&&owner.equals(now.ownerSha)&&contract.equals(now.contractSha)\\n                    &&authorization.equals(now.authorizationSha)&&binding.equals(now.bindingSha)&&generation.equals(now.generation)\\n                    &&instance.equals(now.instance)&&url.equals(now.url)&&display==now.displayId&&window==now.windowId&&now.epoch>=targetEpoch;\\n        }\\n        Map<String,Object> evidence(){return new LinkedHashMap<String,Object>(evidence);}\\n    }\\n    private static PhoneObservation.Node uniqueClick(PhoneObservation frame,WebNativeGeometry geometry,MiPublicProductPage.Link link)throws Exception{\\n        List<PhoneObservation.Node> matches=new ArrayList<PhoneObservation.Node>();\\n        for(PhoneObservation.Node node:frame.nodes)if(link.id.equals(node.viewId))matches.add(node);\\n        if(matches.size()!=1)return null;PhoneObservation.Node node=matches.get(0);\\n        if(!nativeVisible(frame,geometry,node)||!node.clickable||node.editable||node.password||node.scrollable)return null;\\n        String own=node.text.isEmpty()?node.description:node.text;\\n        if(!own.isEmpty())return link.label.equals(own)?node:null;\\n        ObservedChildText.Result child=node.childText;\\n        if(!\\\"derived\\\".equals(child.status)||child.truncated||!child.sourcesComplete||child.sources.isEmpty()\\n                ||!child.rootSignature.matches(\\\"[0-9a-f]{64}\\\")||!child.bind(child.rootSignature).equals(node.observedAppTreeSignature))return null;\\n        Set<String> hashes=new HashSet<String>();for(String text:link.visibleTexts)hashes.add(WebEvidenceJson.sha(text));\\n        boolean model=false;for(ObservedChildText.Source source:child.sources){\\n            if(!source.descendantPath.matches(\\\"[0-9]+(?:/[0-9]+){0,3}\\\")\\n                    ||!(\\\"text\\\".equals(source.property)||\\\"description\\\".equals(source.property))\\n                    ||source.nodeSignature==null||!source.nodeSignature.matches(\\\"[0-9a-f]{64}\\\")||!hashes.contains(source.textSha256))return null;\\n            if(WebEvidenceJson.sha(link.label).equals(source.textSha256))model=true;\\n        }\\n        return model?node:null;\\n    }\\n    private static PhoneObservation.Node uniqueReadable(PhoneObservation frame,WebNativeGeometry geometry,String label){\\n        List<PhoneObservation.Node> matches=new ArrayList<PhoneObservation.Node>();\\n        for(PhoneObservation.Node node:frame.nodes)if(label.equals(node.text.isEmpty()?node.description:node.text))matches.add(node);\\n        if(matches.size()!=1)return null;PhoneObservation.Node node=matches.get(0);\\n        return nativeVisible(frame,geometry,node)&&!node.password&&!node.editable?node:null;\\n    }\\n    private static boolean nativeVisible(PhoneObservation frame,WebNativeGeometry geometry,PhoneObservation.Node node){\\n        return WebEvidenceProtocol.HELPER_PACKAGE.equals(node.packageName)&&node.enabled\\n                &&node.observedAppTreeSignature!=null&&node.observedAppTreeSignature.matches(\\\"[0-9a-f]{64}\\\")\\n                &&geometry.contains(node.bounds.left,node.bounds.top,node.bounds.right,node.bounds.bottom)\\n                &&inside(frame.windowMetadata.rootBounds(),node)&&inside(frame.windowMetadata.windowBounds(),node)\\n                &&node.bounds.left>=0&&node.bounds.top>=0&&node.bounds.right<=frame.width&&node.bounds.bottom<=frame.height;\\n    }\\n    private static boolean inside(int[] r,PhoneObservation.Node node){\\n        return r!=null&&r.length==4&&r[0]<=node.bounds.left&&r[1]<=node.bounds.top&&node.bounds.right<=r[2]&&node.bounds.bottom<=r[3];\\n    }\\n    private static Map<String,Object> nodeEvidence(PhoneObservation.Node node){\\n        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put(\\\"node_id\\\",node.id);out.put(\\\"native_view_id\\\",node.viewId);\\n        out.put(\\\"native_class\\\",node.className);out.put(\\\"native_label\\\",node.label());out.put(\\\"node_app_tree_sha256\\\",node.observedAppTreeSignature);\\n        out.put(\\\"native_bounds\\\",Arrays.asList(node.bounds.left,node.bounds.top,node.bounds.right,node.bounds.bottom));return out;\\n    }\\n    private static Map<String,Object> jsonMap(JSONObject value)throws Exception{\\n        Map<String,Object> out=new LinkedHashMap<String,Object>();java.util.Iterator<String> keys=value.keys();\\n        while(keys.hasNext()){String key=keys.next();out.put(key,jsonValue(value.get(key),0));}return out;\\n    }\\n    private static Object jsonValue(Object value,int depth)throws Exception{\\n        need(depth<=32,\\\"bounded JSON evidence nesting\\\");\\n        if(value==JSONObject.NULL)return null;\\n        if(value instanceof JSONObject){\\n            Map<String,Object> out=new LinkedHashMap<String,Object>();java.util.Iterator<String> keys=((JSONObject)value).keys();\\n            while(keys.hasNext()){String key=keys.next();out.put(key,jsonValue(((JSONObject)value).get(key),depth+1));}return out;\\n        }\\n        if(value instanceof org.json.JSONArray){\\n            List<Object> out=new ArrayList<Object>();org.json.JSONArray a=(org.json.JSONArray)value;\\n            for(int i=0;i<a.length();i++)out.add(jsonValue(a.get(i),depth+1));return out;\\n        }\\n        need(value instanceof String||value instanceof Boolean||value instanceof Number,\\\"JSON scalar evidence required\\\");return value;\\n    }\\n    private static void need(boolean ok,String message){if(!ok)throw new IllegalArgumentException(message);}\\n}\\n\",\n      \"ordered_replacements\": [\n        {\n          \"before\": \"proof.put(\\\"native_geometry\\\",geometry==null?null:geometry.evidence());\",\n          \"after\": \"proof.put(\\\"native_geometry\\\",geometry==null?null:jsonMap(geometry.evidence()));\",\n          \"count\": 1\n        }\n      ],\n      \"final\": {\n        \"bytes\": 31717,\n        \"sha256\": \"bbf256e37eb5cc3a1619371e9c29dc5f7af3139eeb4f602f602cf0f05551bf92\",\n        \"git_blob_sha\": \"78c1c4d616a815dbf31b214f0fb74754745c967c\"\n      },\n      \"final_overlay_entry\": {\n        \"path\": \"src/org/trillionnium/hepta/local/WebShoppingDomain.java\",\n        \"bytes\": 31717,\n        \"sha256\": \"bbf256e37eb5cc3a1619371e9c29dc5f7af3139eeb4f602f602cf0f05551bf92\",\n        \"git_blob_sha\": \"78c1c4d616a815dbf31b214f0fb74754745c967c\",\n        \"base\": {\n          \"bytes\": 25838,\n          \"sha256\": \"f3564aa43c040f02b42b6cb1dbc3b23be7bb847579fea6218f1f625fe5d3c487\",\n          \"git_blob_sha\": \"857099ae7de70dbb6cdd1bcb967a0129168d5e0b\"\n        },\n        \"raw_utf8\": null,\n        \"provenance\": [\n          {\n            \"kind\": \"shopping_final_source\",\n            \"checkpoint_git\": \"9573e144e957893006ef89ce1c3ad6d559d718af\"\n          }\n        ]\n      }\n    },\n    {\n      \"path\": \"tests/warm-finalization/prepare_fixture.py\",\n      \"base_actual_source\": {\n        \"git_blob_sha\": \"07785c82038007af91ba6612d410df5e96d143b2\",\n        \"bytes\": 5713,\n        \"sha256\": \"ae5bccaf044adfb755de0555fdff7d511254a399fb904dc5f103b5a8a36f5bb9\"\n      },\n      \"base_overlay_present\": false,\n      \"base_raw_utf8\": \"\\\"\\\"\\\"Compile exact production Stop and close-result decisions with explicit IO fixtures.\\\"\\\"\\\"\\nimport hashlib\\nimport json\\nfrom pathlib import Path\\n\\n\\ndef section(text, start, end):\\n    if text.count(start) != 1 or text.count(end) != 1:\\n        raise RuntimeError(\\\"production finalization anchors are not unique\\\")\\n    first = text.index(start)\\n    return text[first:text.index(end, first)]\\n\\n\\ndef prepare(source, output):\\n    source = Path(source)\\n    output = Path(output)\\n    output.mkdir(parents=True, exist_ok=True)\\n    package = source / \\\"src/org/trillionnium/hepta/local\\\"\\n    controller = (package / \\\"LocalTaskController.java\\\").read_text(encoding=\\\"utf-8\\\")\\n    inference = (package / \\\"LocalInference.java\\\").read_text(encoding=\\\"utf-8\\\")\\n    service = (package / \\\"HeptaAccessibilityService.java\\\").read_text(encoding=\\\"utf-8\\\")\\n    parts = {\\n        \\\"stop\\\": section(controller, \\\"    public void stop(){\\\", \\\"    @Override public synchronized void close()\\\"),\\n        \\\"close_result\\\": section(controller, \\\"            LocalInference.TaskCleanup modelCleanup;\\\", \\\"            if(completionInstalled!=null)try{completionInstalled.verify(service);}catch(Exception changed){\\\\n\\\"),\\n        \\\"cleanup_contract\\\": section(inference, \\\"    final class TaskCleanup {\\\", \\\"    interface Handle {\\\"),\\n        \\\"message_helpers\\\": section(service, \\\"    static String limited(\\\", \\\"\\\\n}\\\"),\\n    }\\n    local_inference = (\\n        \\\"package org.trillionnium.hepta.local;\\\\n\\\"\\n        \\\"public interface LocalInference {\\\\n\\\"\\n        + parts[\\\"cleanup_contract\\\"]\\n        + \\\"void cancelTask();\\\\nTaskCleanup endTask();\\\\n}\\\\n\\\"\\n    )\\n    fixture = \\\"\\\"\\\"package org.trillionnium.hepta.local;\\nimport java.util.concurrent.atomic.AtomicBoolean;\\npublic final class ControllerFinalizationFixture {\\n    private final LocalInference inference;\\n    private final AtomicBoolean cancelled=new AtomicBoolean();\\n    private final Object handleLock=new Object();\\n    private volatile boolean running=true,blocked;\\n    private Handle activeInference;\\n    /** Scope/config IO seam; default absent preserves all original 13 cases. */\\n    public interface ScopeCheck { void verifyUnchanged() throws Exception; }\\n    private ScopeCheck scope;\\n    /** Admitted/live Owner authorization seam; actual admission runs in the controller harness. */\\n    private interface AuthorizationFrame { boolean successAllowed(); }\\n    private interface AuthorizationCheck { void ready(); AuthorizationFrame frame(); }\\n    private final AuthorizationCheck authorization=new AuthorizationCheck(){\\n        public void ready(){}\\n        public AuthorizationFrame frame(){throw new AssertionError(\\\"legacy fixture has no controller-workflow candidate\\\");}\\n    };\\n    public void setScopeCheck(ScopeCheck check){scope=check;}\\n    private interface Handle { void cancel(); }\\n    private void emit(String value) { /* Android listener fixture; no IO. */ }\\n    public ControllerFinalizationFixture(LocalInference inference){this.inference=inference;}\\n    public static final class Outcome {\\n        public final String status,summary;\\n        public final boolean modelSuccess,cleanupKnown,blocked;\\n        Outcome(String status,String summary,boolean success,boolean cleanup,boolean blocked){\\n            this.status=status;this.summary=summary;this.modelSuccess=success;\\n            this.cleanupKnown=cleanup;this.blocked=blocked;\\n        }\\n    }\\n\\\"\\\"\\\" + parts[\\\"stop\\\"] + \\\"\\\"\\\"\\n    public Outcome finish(String previousStatus,String previousSummary,boolean previousSuccess,\\n                          boolean previousCleanup,boolean previouslyBlocked){\\n        String taskId=\\\"33333333333333333333333333333333\\\";\\n        String finalStatus=previousStatus,summary=previousSummary;\\n        boolean modelSuccess=previousSuccess,cleanup=previousCleanup,controllerSuccess=false;\\n        blocked=previouslyBlocked;\\n\\\"\\\"\\\" + parts[\\\"close_result\\\"] + \\\"\\\"\\\"\\n        running=false;\\n        return new Outcome(finalStatus,summary,modelSuccess,cleanup,blocked);\\n    }\\n}\\n\\\"\\\"\\\"\\n    service_fixture=\\\"package org.trillionnium.hepta.local;\\\\nfinal class HeptaAccessibilityService {\\\\n\\\"+parts[\\\"message_helpers\\\"]+\\\"\\\\n}\\\\n\\\"\\n    files = []\\n    for name, value in ((\\\"LocalInference.java\\\", local_inference),\\n                        (\\\"ControllerFinalizationFixture.java\\\", fixture),\\n                        (\\\"HeptaAccessibilityService.java\\\", service_fixture)):\\n        path = output / name\\n        path.write_text(value, encoding=\\\"utf-8\\\")\\n        files.append(path)\\n    digest = lambda value: hashlib.sha256(value).hexdigest()\\n    record = {\\n        \\\"scope\\\": \\\"Exact production Stop method, endTask/exception handling, post-close scope check, terminal decisions and TaskCleanup; Android UI, model and scope/config IO are fixtures\\\",\\n        \\\"completion_boundary\\\": \\\"Exact production cleanup/status block; controller-workflow candidate is false in this legacy fixture, while the derived terminal and completion identity execute in the full-controller harness\\\",\\n        \\\"scope_io_default\\\": \\\"absent; all original 13 cases retained; configured production checks also run in qualification-scope full-controller harness\\\",\\n        \\\"controller_sha256\\\": digest(controller.encode()),\\n        \\\"inference_sha256\\\": digest(inference.encode()),\\n        \\\"service_sha256\\\": digest(service.encode()),\\n        \\\"extracted_parts\\\": {name: {\\\"bytes\\\": len(value.encode()), \\\"sha256\\\": digest(value.encode())}\\n                            for name, value in parts.items()},\\n        \\\"generated_files\\\": {path.name: digest(path.read_bytes()) for path in files},\\n        \\\"not_android_runtime\\\": True,\\n        \\\"not_model_inference\\\": True,\\n        \\\"not_phone_test\\\": True,\\n    }\\n    (output / \\\"EXTRACTION.json\\\").write_text(json.dumps(record, indent=2) + \\\"\\\\n\\\", encoding=\\\"utf-8\\\")\\n    return files, record\\n\",\n      \"ordered_replacements\": [\n        {\n          \"before\": \"    private volatile boolean running=true,blocked;\",\n          \"after\": \"    private volatile boolean running=true,blocked,terminalDecisionSealed;\",\n          \"count\": 1\n        },\n        {\n          \"before\": \"    /** Admitted/live Owner authorization seam; actual admission runs in the controller harness. */\\n    private interface AuthorizationFrame { boolean successAllowed(); }\\n    private interface AuthorizationCheck { void ready(); AuthorizationFrame frame(); }\\n    private final AuthorizationCheck authorization=new AuthorizationCheck(){\\n        public void ready(){}\\n        public AuthorizationFrame frame(){throw new AssertionError(\\\"legacy fixture has no controller-workflow candidate\\\");}\\n    };\",\n          \"after\": \"    /** Type-only Owner boundary; this legacy fixture cannot create an authorized Frame. */\\n    private static final class TaskAuthorization {\\n        private interface Frame { boolean successAllowed(); }\\n    }\\n    private interface AuthorizationCheck { void ready(); TaskAuthorization.Frame frame(); }\\n    private final AuthorizationCheck authorization=new AuthorizationCheck(){\\n        public void ready(){}\\n        public TaskAuthorization.Frame frame(){throw new AssertionError(\\\"legacy fixture has no controller-workflow candidate\\\");}\\n    };\\n    /** Explicit non-Web contract; no helper close proof or Web completion is provided. */\\n    private static final class TaskCompletionGate {\\n        private static final String WEB=\\\"web_search_results\\\";\\n        private static final class Contract { private final String kind=\\\"unverified_goal\\\"; }\\n        private final Contract contract=new Contract();\\n    }\\n    private final TaskCompletionGate completion=new TaskCompletionGate();\",\n          \"count\": 1\n        }\n      ],\n      \"final\": {\n        \"bytes\": 6220,\n        \"sha256\": \"e4ee5ea79e689a2e89d64f5c8092a523e77ab5a337c5965c34a32974d06092e1\",\n        \"git_blob_sha\": \"b55a5e693c29035d94e1140c77b299f8fce56d1c\"\n      },\n      \"final_overlay_entry\": {\n        \"path\": \"tests/warm-finalization/prepare_fixture.py\",\n        \"bytes\": 6220,\n        \"sha256\": \"e4ee5ea79e689a2e89d64f5c8092a523e77ab5a337c5965c34a32974d06092e1\",\n        \"git_blob_sha\": \"b55a5e693c29035d94e1140c77b299f8fce56d1c\",\n        \"base\": {\n          \"git_blob_sha\": \"07785c82038007af91ba6612d410df5e96d143b2\",\n          \"bytes\": 5713,\n          \"sha256\": \"ae5bccaf044adfb755de0555fdff7d511254a399fb904dc5f103b5a8a36f5bb9\"\n        },\n        \"raw_utf8\": null,\n        \"provenance\": \"Main56 actual Core r1 fixture type completion; original production extraction and Java assertions unchanged.\"\n      }\n    }\n  ],\n  \"final_overlay_order\": [\n    \"AndroidManifest.xml\",\n    \"src/org/trillionnium/hepta/local/CsairCalendar.java\",\n    \"src/org/trillionnium/hepta/local/CsairCityPicker.java\",\n    \"src/org/trillionnium/hepta/local/CsairFlightForm.java\",\n    \"src/org/trillionnium/hepta/local/HeptaAccessibilityService.java\",\n    \"src/org/trillionnium/hepta/local/LocalTaskController.java\",\n    \"src/org/trillionnium/hepta/local/MiPublicProductPage.java\",\n    \"src/org/trillionnium/hepta/local/PhoneObservation.java\",\n    \"src/org/trillionnium/hepta/local/TaskCompletionGate.java\",\n    \"src/org/trillionnium/hepta/local/WebEvidenceClient.java\",\n    \"src/org/trillionnium/hepta/local/WebEvidenceReceipt.java\",\n    \"src/org/trillionnium/hepta/local/WebFlightDomain.java\",\n    \"src/org/trillionnium/hepta/local/WebFlightSession.java\",\n    \"src/org/trillionnium/hepta/local/WebHelperIdentity.java\",\n    \"src/org/trillionnium/hepta/local/WebNativeGeometry.java\",\n    \"src/org/trillionnium/hepta/local/WebRegionNativeBridge.java\",\n    \"src/org/trillionnium/hepta/local/WebShoppingDomain.java\",\n    \"src/org/trillionnium/hepta/local/WebTaskDomain.java\",\n    \"src/org/trillionnium/hepta/local/web/WebShoppingGoal.java\",\n    \"src/org/trillionnium/hepta/webprotocol/WebDomCanonical.java\",\n    \"src/org/trillionnium/hepta/webprotocol/WebDomStability.java\",\n    \"src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java\",\n    \"src/org/trillionnium/hepta/webprotocol/WebMiActionRegion.java\",\n    \"src/org/trillionnium/hepta/webprotocol/WebObservedNavigation.java\",\n    \"src/org/trillionnium/hepta/webprotocol/WebRecoveryPolicy.java\",\n    \"src/org/trillionnium/hepta/webprotocol/WebSitePolicy.java\",\n    \"tests/exact-admission/org/json/JSONArray.java\",\n    \"tests/exact-admission/org/json/JSONObject.java\",\n    \"tests/qualification-scope/BackgroundObservationFixture.template\",\n    \"tests/qualification-scope/ServiceFixture.template\",\n    \"tests/qualification-scope/fixtures/org/json/JSONObject.java\",\n    \"tests/qualification-scope/fixtures/org/trillionnium/hepta/local/BackgroundSession.java\",\n    \"tests/qualification-scope/fixtures/org/trillionnium/hepta/local/WebFlightSession.java\",\n    \"tests/qualification-scope/prepare_fixture.py\",\n    \"tests/web-flight/legacy-boundary/WebFlightDomain.java\",\n    \"tests/web-flight/run_query_host_tests.py\",\n    \"tests/calculator-input/CalculatorInputGuardHostTest.java\",\n    \"src/org/trillionnium/hepta/local/WebFlightNativeStability.java\",\n    \"tests/completion/TaskCompletionGateHostTest.java\",\n    \"tests/warm-finalization/prepare_fixture.py\"\n  ],\n  \"top_level_replacements\": [\n    {\n      \"key\": \"status\",\n      \"before_present\": true,\n      \"before\": \"source-only complete Main56 Flight homepage stability and immutable terminal-proof successor; same595 source required for actual Core/Web/Android gates; not compiled, signed, published or installed\",\n      \"after\": \"Source-only same595 successor to actual Core56 r1 and Web56 r1 failures: two fixture type hunks and one Shopping evidence-boundary hunk; no successor build/sign/phone pass claimed.\"\n    },\n    {\n      \"key\": \"overlay_file_count\",\n      \"before_present\": true,\n      \"before\": 39,\n      \"after\": 40\n    },\n    {\n      \"key\": \"base_rows_replaced_in_candidate\",\n      \"before_present\": true,\n      \"before\": 33,\n      \"after\": 34\n    },\n    {\n      \"key\": \"base_rows_retained_byte_identically\",\n      \"before_present\": true,\n      \"before\": 556,\n      \"after\": 555\n    },\n    {\n      \"key\": \"main56_current_successor\",\n      \"before_present\": true,\n      \"before\": {\n        \"schema\": \"hepta.main56-bounded-flight-stability-source-successor.v1\",\n        \"actual55_source_commit\": \"dd2cd48054c2c6f0b2597b7d9be05edd8ce6b34e\",\n        \"reconstruction_base_source_commit\": \"42d3a0f447807659c0f78c8273edee01dd1b734f\",\n        \"predecessor_nested_successor_and_frozen_input_fields_are_historical\": true,\n        \"changed_existing_paths\": [\n          \"AndroidManifest.xml\",\n          \"src/org/trillionnium/hepta/local/HeptaAccessibilityService.java\",\n          \"src/org/trillionnium/hepta/local/LocalTaskController.java\",\n          \"src/org/trillionnium/hepta/local/TaskCompletionGate.java\",\n          \"src/org/trillionnium/hepta/local/WebFlightSession.java\",\n          \"tests/completion/TaskCompletionGateHostTest.java\",\n          \"tests/qualification-scope/BackgroundObservationFixture.template\",\n          \"tests/qualification-scope/ServiceFixture.template\",\n          \"tests/qualification-scope/fixtures/org/trillionnium/hepta/local/WebFlightSession.java\",\n          \"tests/qualification-scope/prepare_fixture.py\",\n          \"tests/web-flight/run_query_host_tests.py\"\n        ],\n        \"new_paths\": [\n          \"src/org/trillionnium/hepta/local/WebFlightNativeStability.java\"\n        ],\n        \"ordered_hunks_on_existing_paths\": 61,\n        \"unchanged_actual55_source_rows\": 583,\n        \"all_other_actual55_source_rows_byte_identical\": true,\n        \"version_code\": 56,\n        \"version_name\": \"0.56.0-flight-stability\",\n        \"final_source_inventory\": {\n          \"schema\": \"bare-array-path-bytes-sha256\",\n          \"bytes\": 103795,\n          \"sha256\": \"4581b1c7cfe27caf4e3d24562072baa511705f3e13205fc8720021bba9cc4512\",\n          \"git_blob_sha\": \"89e9aaec004f6b07a7b60b24d9e1fba397e924cc\"\n        },\n        \"full_inventory\": {\n          \"bytes\": 163370,\n          \"sha256\": \"71ad8ef4ea1023850c950282d57bcae3e73877e5e6a7ad582b58951e1ba7001e\",\n          \"git_blob_sha\": \"31cc40c2c8a97aa1b1e01b15805da240a543e052\"\n        },\n        \"external_web_fixtures\": {\n          \"composition\": {\n            \"git\": \"c27618f05e5d6aaf0af5f38ac7f8dbb261366d5a\",\n            \"bytes\": 51438,\n            \"sha256\": \"a6cbef2e5a4be11aa38a8e5b20f49f65e6b1deaef51fe20ba3153ae0e49c54a1\"\n          },\n          \"native_stability_cases\": {\n            \"git\": \"71c9626ef7ddeafdc4fbd6dd7bc12fc9b1dee443\",\n            \"bytes\": 53708,\n            \"sha256\": \"c787261dd3953bb933560cd19b7ccc6fa0c34c56c122cf018664ce9b12afc2ca\"\n          },\n          \"source_tree_legacy_composition_unchanged\": true\n        },\n        \"current_focused39_production_changed\": true,\n        \"old_focused39_is_not_current_execution_proof\": true,\n        \"actual_flight_results_provider_ready\": false,\n        \"actual_business_verified\": false,\n        \"source_reviews\": [\n          \"98173deeb9f2b85f9e4ae5e8544607f60b084fe6\",\n          \"16f4ec635d4ee845b4c120f3ed13a83600a5d46c\",\n          \"a4be28db3b78686bff6be2ecceffe2b9ca518e9c\",\n          \"0c35f07f5efb823eaeff503d06cfe810edc96fed\"\n        ],\n        \"actual_compiled\": false,\n        \"actual_host_checks_executed\": false\n      },\n      \"after\": {\n        \"schema\": \"hepta.main56-bounded-flight-stability-source-successor.v1\",\n        \"actual55_source_commit\": \"dd2cd48054c2c6f0b2597b7d9be05edd8ce6b34e\",\n        \"reconstruction_base_source_commit\": \"42d3a0f447807659c0f78c8273edee01dd1b734f\",\n        \"predecessor_nested_successor_and_frozen_input_fields_are_historical\": true,\n        \"changed_existing_paths\": [\n          \"AndroidManifest.xml\",\n          \"src/org/trillionnium/hepta/local/HeptaAccessibilityService.java\",\n          \"src/org/trillionnium/hepta/local/LocalTaskController.java\",\n          \"src/org/trillionnium/hepta/local/TaskCompletionGate.java\",\n          \"src/org/trillionnium/hepta/local/WebFlightSession.java\",\n          \"src/org/trillionnium/hepta/local/WebShoppingDomain.java\",\n          \"tests/completion/TaskCompletionGateHostTest.java\",\n          \"tests/qualification-scope/BackgroundObservationFixture.template\",\n          \"tests/qualification-scope/ServiceFixture.template\",\n          \"tests/qualification-scope/fixtures/org/trillionnium/hepta/local/WebFlightSession.java\",\n          \"tests/qualification-scope/prepare_fixture.py\",\n          \"tests/warm-finalization/prepare_fixture.py\",\n          \"tests/web-flight/run_query_host_tests.py\"\n        ],\n        \"new_paths\": [\n          \"src/org/trillionnium/hepta/local/WebFlightNativeStability.java\"\n        ],\n        \"ordered_hunks_on_existing_paths\": 64,\n        \"unchanged_actual55_source_rows\": 581,\n        \"all_other_actual55_source_rows_byte_identical\": true,\n        \"version_code\": 56,\n        \"version_name\": \"0.56.0-flight-stability\",\n        \"final_source_inventory\": {\n          \"schema\": \"bare-array-path-bytes-sha256\",\n          \"bytes\": 103795,\n          \"sha256\": \"ca24673843908c7f9343c949af64b8393e69ce53605128782036ae9ce9d1f46e\",\n          \"git_blob_sha\": \"c43a4be934ca00942ceeed086e16fc4b81d3a519\"\n        },\n        \"full_inventory\": {\n          \"bytes\": 163370,\n          \"sha256\": \"d87173f40a5f2793e077408674f2f8a24b8152d74f5fd01cdcdf5fd403ebd386\",\n          \"git_blob_sha\": \"0a548d1541ad07fb4965d7e2d411c16fdff422db\"\n        },\n        \"external_web_fixtures\": {\n          \"composition\": {\n            \"git\": \"d1052b460b32020a5e7bfb061623d9447a13e597\",\n            \"bytes\": 53410,\n            \"sha256\": \"35c0702df7ff94e261dadbc219bc4afe7ddba8f72cc2cd5ec23f8acb0771f68e\"\n          },\n          \"native_stability_cases\": {\n            \"git\": \"71c9626ef7ddeafdc4fbd6dd7bc12fc9b1dee443\",\n            \"bytes\": 53708,\n            \"sha256\": \"c787261dd3953bb933560cd19b7ccc6fa0c34c56c122cf018664ce9b12afc2ca\"\n          },\n          \"source_tree_legacy_composition_unchanged\": true\n        },\n        \"current_focused39_production_changed\": true,\n        \"old_focused39_is_not_current_execution_proof\": true,\n        \"actual_flight_results_provider_ready\": false,\n        \"actual_business_verified\": false,\n        \"source_reviews\": [\n          \"98173deeb9f2b85f9e4ae5e8544607f60b084fe6\",\n          \"16f4ec635d4ee845b4c120f3ed13a83600a5d46c\",\n          \"a4be28db3b78686bff6be2ecceffe2b9ca518e9c\",\n          \"0c35f07f5efb823eaeff503d06cfe810edc96fed\",\n          \"d4636cd0a6b0d2b588d3d29eb208c09eb6bbc7b4\",\n          \"26e458e65ef259e0fd26c68adbaac558d51cc6dd\"\n        ],\n        \"actual_compiled\": false,\n        \"actual_host_checks_executed\": false\n      }\n    },\n    {\n      \"key\": \"main56_r1_failure_repair\",\n      \"before_present\": false,\n      \"before\": null,\n      \"after\": {\n        \"schema\": \"hepta.main56-observed-core-and-web-failure-repair.v1\",\n        \"predecessor\": {\n          \"bytes\": 1416544,\n          \"sha256\": \"38baa995ee76520e1a9ff7a14baf51afdbd4f1af53f747ce7a0d114ef4809c90\",\n          \"git_blob_sha\": \"660335b7f19f519af4cfd168ebee186f1a4693b9\"\n        },\n        \"actual_core_r1_failure\": {\n          \"git_blob_sha\": \"3274c9f9254450635364967eb3701ad30056910c\",\n          \"bytes\": 8174,\n          \"sha256\": \"df5c72a750e8ffc51fcb798565849157a9fbdfd2386314c305782cf7c96d2dc5\"\n        },\n        \"actual_core_r1_javac_log\": {\n          \"git_blob_sha\": \"7367b41bc7fe35f428fe40698c21da30b0c50284\",\n          \"bytes\": 1567,\n          \"sha256\": \"0fc8f7fb1d2ef48d95903068d5da303dc80d37f9f07c7f4999acc3f314d2ee67\"\n        },\n        \"actual_web_r1_failure\": {\n          \"git_blob_sha\": \"30962e2f30d7b0309aaacd44d67e795e436752ee\",\n          \"bytes\": 29724,\n          \"sha256\": \"f9bf137d294e385c6cd85987a10ba682fdb9bb8415fa51a005e5ff871914eec4\"\n        },\n        \"actual_web_r1_stderr\": {\n          \"git_blob_sha\": \"b437fd9854666141f78911df0a7b53c9de376165\",\n          \"bytes\": 1012,\n          \"sha256\": \"242466b11bebf08dc48246b949fb506dc8bde71bba0c7be798c0fa98d6b0ef75\"\n        },\n        \"changed_paths\": [\n          \"src/org/trillionnium/hepta/local/WebShoppingDomain.java\",\n          \"tests/warm-finalization/prepare_fixture.py\"\n        ],\n        \"production_changed_paths\": [\n          \"src/org/trillionnium/hepta/local/WebShoppingDomain.java\"\n        ],\n        \"test_only_changed_paths\": [\n          \"tests/warm-finalization/prepare_fixture.py\"\n        ],\n        \"ordered_hunks\": 3,\n        \"old_other593_rows_byte_identical\": true,\n        \"tcg_and_ltc_unchanged\": true,\n        \"existing_jsonMap_converter_reused\": true,\n        \"original_unknown_type_and_bounded_deep_freeze_guards_unchanged\": true,\n        \"old_Java_assertions_unchanged\": true,\n        \"external_composition_added_assertions\": 4,\n        \"external_composition_added_cases\": 0,\n        \"actual_android_compiler_map_changed_paths\": [\n          \"src/org/trillionnium/hepta/local/WebShoppingDomain.java\"\n        ],\n        \"actual_compilation_of_successor\": false,\n        \"all_gate_inputs_must_bind_this_same_source\": true,\n        \"no_fixture_only_intermediate_run\": true,\n        \"original_failures_preserved\": true,\n        \"source_delta_refs\": [\n          {\n            \"git_blob_sha\": \"4853e37309edf1c796775007e004fa461f72b0ac\",\n            \"bytes\": 34913,\n            \"sha256\": \"7de95422ab7907e8e5714fb9c910e3af66082dbd03e04098ae1a232408206654\"\n          },\n          {\n            \"git_blob_sha\": \"0efa5aec1a01576aa7edb6872e5d4635671321ed\",\n            \"bytes\": 10765,\n            \"sha256\": \"d078f08fafa777736dbe422874180185d7b692b32025baa8c280044bd8a172b0\"\n          }\n        ],\n        \"external_composition_delta\": {\n          \"git_blob_sha\": \"646892f142a8ada4657fcf9613c3f2c8e560fc4e\",\n          \"bytes\": 58894,\n          \"sha256\": \"cd861f247da01c21423e45e77195558e1700a4a2d72efda44ca210cc48cc1b92\"\n        },\n        \"source_review\": {\n          \"git_blob_sha\": \"d4636cd0a6b0d2b588d3d29eb208c09eb6bbc7b4\",\n          \"bytes\": 2163,\n          \"sha256\": \"ee16415eb0cee6c339c7d7880f7c1508ee208977d34edaa5d10dff345a741b82\"\n        },\n        \"execution\": {\n          \"host_checks\": false,\n          \"compiled\": false,\n          \"signed\": false,\n          \"published\": false,\n          \"phone_actions\": 0,\n          \"actual_results_provider_ready\": false,\n          \"business_verified\": false\n        }\n      }\n    }\n  ],\n  \"inventory\": {\n    \"schema\": \"hepta.main56-source-candidate-inventory.v1\",\n    \"expected_file_count\": 595,\n    \"full_inventory\": {\n      \"bytes\": 163370,\n      \"sha256\": \"d87173f40a5f2793e077408674f2f8a24b8152d74f5fd01cdcdf5fd403ebd386\",\n      \"git_blob_sha\": \"0a548d1541ad07fb4965d7e2d411c16fdff422db\"\n    },\n    \"physical_inventory\": {\n      \"bytes\": 103795,\n      \"sha256\": \"ca24673843908c7f9343c949af64b8393e69ce53605128782036ae9ce9d1f46e\",\n      \"git_blob_sha\": \"c43a4be934ca00942ceeed086e16fc4b81d3a519\"\n    },\n    \"full_inventory_order\": \"lexicographic path code-point\",\n    \"physical_inventory_order\": \"Python pathlib.Path lexicographic POSIX-component tuples\",\n    \"row_keys\": [\n      \"path\",\n      \"bytes\",\n      \"sha256\",\n      \"git_blob_sha\",\n      \"mode\"\n    ]\n  },\n  \"mechanical_checks\": {\n    \"three_ordered_hunks_forward_reverse_exact\": true,\n    \"changed_source_rows\": 2,\n    \"production_rows\": 1,\n    \"fixture_rows\": 1,\n    \"other593_rows_byte_identical\": true,\n    \"aggregate_json_reconstruction\": true\n  },\n  \"execution\": {\n    \"host_checks\": false,\n    \"java_compiled\": false,\n    \"android_build\": false,\n    \"phone_actions\": 0\n  }\n}\n".encode("utf-8","strict")
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
         "original core101 parent must exit normally")


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

def load_digest(path,digest,original_facts):
    raw,facts=read_regular(path)
    need(sha(raw)==digest,"full original digest: "+str(path))
    original_facts.append(facts)
    return raw,facts

def derive_current_successor(prior, prior_source, delta):
    need(delta["schema"]=="hepta.main56-r1-failure-repair-aggregate-exact-delta.v1",
         "reviewed exact repair of the actual56r1 source tree")
    current=strict(encoded(prior))
    target=dict(prior_source)
    overlays={item["path"]:item for item in current["files"]}
    inventory={item["path"]:item for item in current["inventory"]["files"]}
    need(len(overlays)==39 and len(inventory)==595 and len(delta["files"])==2,
         "complete actual56r1 aggregate and two reviewed repairs")
    original_order=[item["path"] for item in current["files"]]
    changed=[]
    for item in delta["files"]:
        name=relative(item["path"]);need(name not in changed and name in target,"unique existing exact delta path")
        changed.append(name)
        old=checked(target[name],item["base_actual_source"],"exact actual56r1 delta predecessor")
        need(type(item["base_raw_utf8"]) is str and item["base_raw_utf8"].encode("utf-8","strict")==old,
             "reviewed full predecessor equals actual source bytes")
        need(type(item["base_overlay_present"]) is bool
             and item["base_overlay_present"] is (name in overlays),"actual predecessor overlay membership")
        if item["base_overlay_present"]:
            need(overlays[name]["raw_utf8"].encode("utf-8","strict")==old,"original overlay bytes unchanged")
        else:
            need(name=="tests/warm-finalization/prepare_fixture.py",
                 "only the original finalization generator is newly overlaid")
        text=old.decode("utf-8","strict")
        for patch in item["ordered_replacements"]:
            need(set(patch)=={"before","after","count"} and type(patch["count"]) is int and patch["count"]==1
                 and type(patch["before"]) is str and type(patch["after"]) is str
                 and patch["before"]!="" and text.count(patch["before"])==1,
                 "one exact ordered source hunk")
            text=text.replace(patch["before"],patch["after"],1)
        raw=text.encode("utf-8","strict")
        reverse=text
        for patch in reversed(item["ordered_replacements"]):
            need(patch["after"]!="" and reverse.count(patch["after"])==1,"one reverse source hunk")
            reverse=reverse.replace(patch["after"],patch["before"],1)
        need(reverse.encode("utf-8","strict")==old,"source delta reverses to the full actual original")
        checked(raw,item["final"],"full successor source identity")
        entry=strict(encoded(item["final_overlay_entry"]))
        need(entry["path"]==name and entry["raw_utf8"] is None,"metadata-only reviewed overlay template")
        checked(raw,entry,"exact final overlay identity")
        entry["raw_utf8"]=raw.decode("utf-8","strict")
        overlays[name]=entry
        inventory[name]={"path":name,"bytes":len(raw),"sha256":sha(raw),"git_blob_sha":blob(raw),
                         "mode":inventory[name]["mode"]}
        target[name]=raw
    need(sorted(name for name in prior_source if prior_source[name]!=target[name])==CONFIG["changed_existing_paths"]
         and set(target)==set(prior_source) and CONFIG["new_paths"]==[]
         and sum(target[name]==raw for name,raw in prior_source.items())==CONFIG["unchanged_prior_source_rows"],
         "only Shopping evidence conversion and finalization fixture differ; other593 remain exact")
    order=delta["final_overlay_order"]
    need(type(order) is list and len(order)==len(set(order))==len(overlays)==40
         and set(order)==set(overlays)
         and order==original_order+["tests/warm-finalization/prepare_fixture.py"],
         "original39 overlay order retained plus the one existing test generator")
    current["files"]=[overlays[name] for name in order]
    current["inventory"]={"schema":delta["inventory"]["schema"],
                          "bytes":delta["inventory"]["full_inventory"]["bytes"],
                          "sha256":delta["inventory"]["full_inventory"]["sha256"],
                          "files":[inventory[name] for name in sorted(inventory)]}
    for patch in delta["top_level_replacements"]:
        name=patch["key"]
        need((name in current) is patch["before_present"]
             and current.get(name)==patch["before"],"exact prior top-level metadata "+name)
        current[name]=patch["after"]
    raw=checked(encoded(current),CONFIG["aggregate"],"complete final aggregate after exact derivation")
    validate_map(target,current["inventory"]["files"],True)
    need(current["main56_current_successor"]["actual_flight_results_provider_ready"] is False,
         "source successor does not invent a flight-results provider")
    return current,raw,target

def prior_core_evidence(root,original_facts):
    records={}
    def keep(name,pin=None):
        relative(name)
        if name in records:
            if pin is not None:checked(records[name][0],pin,"pinned actual56r1 original "+name)
            return records[name][0]
        raw,facts=read_regular(root/name,pin)
        records[name]=(raw,facts);original_facts.append(facts)
        return raw
    result=strict(keep("RESULT.json",CONFIG["prior_core_result"]))
    keep("stage.py",CONFIG["prior_core_source"])
    keep("AGGREGATE.json",CONFIG["prior_aggregate"])
    keep("SOURCE-INVENTORY.json",CONFIG["prior_inventory"])
    keep("SOURCE-BLOB-MAP.json",CONFIG["prior_source_blob_map"])
    keep("COMPILER-INPUTS.json",CONFIG["prior_compiler_inputs"])
    for name in ("CONFIG.json","EXPECTED-HOST-INPUTS.json","START-ARGS.json","ERROR.txt","SUMMARY.json"):
        keep(name)
    host=strict(keep("host-checks/HOST-CHECKS.json",CONFIG["prior_host_checks"]))
    need(result["schema"]=="hepta.main56-original-core101-host-stage.v1"
         and result["all_pass"] is False and type(result["exit_code"]) is int and result["exit_code"]==1
         and result["originals_unchanged"] is True and result["source_unchanged"] is True
         and result["prior_core_evidence_unchanged"] is True
         and result["source_file_count"]==595 and result["host_check_count"]==58
         and result["host_input_count"]==419 and result["nested_completion_stage_count"]==0
         and result["source_inventory_sha256"]==CONFIG["prior_inventory"]["sha256"]
         and result["stage_sha256"]==CONFIG["prior_core_source"]["sha256"],
         "actual56r1 failure retained with its full source and original provenance")
    need(len(result["steps"])==1 and result["steps"][0]["exit_code"]==1
         and result["steps"][0]["exit_observed"] is True
         and result["steps"][0]["timed_out"] is False and result["steps"][0]["forced_kill"] is False
         and result["steps"][0]["owned_group_absent_observed_after_failure"] is True,
         "actual56r1 failed child exited and its owned group was observed absent")
    for suffix in ("stdout","stderr"):
        pin=result["steps"][0][suffix]
        need(pin["path"]==str(root/("original-host-checks."+suffix)),"fixed prior parent log path")
        keep("original-host-checks."+suffix,pin)
    summary=strict(keep("SUMMARY.json"))
    need(summary["all_pass"] is False
         and summary["result"]["sha256"]==CONFIG["prior_core_result"]["sha256"],
         "completed actual56r1 summary continues to bind its failed result")
    need(host["schema"]=="hepta.host-checks.v3" and host["all_pass"] is False
         and len(host["checks"])==58 and host["checks"][-1]["name"]=="background-client"
         and [row["exit_code"] for row in host["checks"]]==[0]*57+[1],
         "exact original58 records and observed first background-client failure")
    for row in host["checks"]:
        name=relative(row["name"]);need("/" not in name,"simple prior host check")
        for suffix in ("stdout","stderr"):
            raw=keep("host-checks/"+name+"."+suffix)
            need(sha(raw)==row[suffix+"_sha256"],"full prior original host log")
    keep("host-checks/background-client.stdout",CONFIG["prior_failed_stdout"])
    validation=strict(keep("host-checks/background-client/VALIDATION.json"))
    need(validation["status"]=="failed" and len(validation["stages"])==1
         and validation["stages"][0]["name"]=="compile" and validation["stages"][0]["exit_code"]==1,
         "actual background-client javac failure precedes its test execution")
    for name in ("compile.stdout","compile.stderr","fixture/EXTRACTION.json","fixture/terminal/EXTRACTION.json"):
        keep("host-checks/background-client/"+name)
    extraction=strict(keep("host-checks/background-client/fixture/terminal/EXTRACTION.json"))
    for name,digest in extraction["generated_files"].items():
        relative(name);need("/" not in name,"simple original finalization fixture member")
        raw=keep("host-checks/background-client/fixture/terminal/"+name)
        need(sha(raw)==digest,"actual failed generated source byte identity")
    return {name:facts for name,(_,facts) in sorted(records.items())}

# Pure host101 consumes reviewed sources, not an Android-build output.
# The exact repairs are derived from the actual56r1 aggregate and source tree.
# Its failed result remains unchanged; all current bytes are bound before mutation.
stage_raw=globals().get("__stage_source__")
need(type(stage_raw) is bytes and len(stage_raw)>0,"exact loader-verified stage bytes")
ROOT=Path(CONFIG["root"])
SOURCE=Path(CONFIG["source_root"])
PRIOR=Path(CONFIG["prior_root"])
need(sys.platform=="linux" and SOURCE==ROOT/"source","fixed new Pocket4 source tree")
need(ROOT.is_absolute() and not ROOT.exists() and not ROOT.is_symlink()
     and PRIOR not in ROOT.parents and ROOT not in PRIOR.parents,"independent new output root")
for field in ("source_file_count","compiler_input_count","java_source_count","host_input_count",
              "expected_top_level_checks","timeout_seconds"):
    need(type(CONFIG[field]) is int and CONFIG[field]>0,"sealed expected count "+field)
checked(DELTA_RAW,CONFIG["delta"],"complete reviewed56 exact delta")
delta=strict(DELTA_RAW)
need(delta["base_aggregate"]=={k:v for k,v in CONFIG["prior_aggregate"].items() if k!="path"}
     and delta["result_aggregate"]==CONFIG["aggregate"],"fixed predecessor and successor aggregate pins")
original_facts=[]
prior_evidence=prior_core_evidence(PRIOR,original_facts)
prior_aggregate_raw=unchanged(prior_evidence["AGGREGATE.json"])
aggregate=strict(prior_aggregate_raw)
prior_source,prior_source_facts=snapshot(PRIOR/"source")
validate_map(prior_source,aggregate["inventory"]["files"],True)
checked(encoded(rows(prior_source)),CONFIG["prior_inventory"],"full actual56r1 source inventory")
need(len(prior_source)==CONFIG["prior_source_file_count"]==595,"complete immutable actual56r1 source tree")
original_facts.extend(prior_source_facts.values())
prior_overlay_names=set()
for item in aggregate["files"]:
    name=relative(item["path"])
    need(name not in prior_overlay_names,"unique actual56r1 overlay")
    prior_overlay_names.add(name)
    raw=item["raw_utf8"].encode("utf-8","strict")
    checked(raw,item,"full actual56r1 aggregate overlay")
    need(prior_source[name]==raw,"actual56r1 source equals its archived aggregate overlay")
need(len(prior_overlay_names)==39,"all actual56r1 overlay sources")
aggregate,aggregate_raw,before=derive_current_successor(aggregate,prior_source,delta)
before_facts=None
inventory_raw=checked(encoded(rows(before)),CONFIG["inventory"],"exact reviewed595 source inventory")
need(len(before)==CONFIG["source_file_count"]==595,"complete current source count")
identity_raw=checked(before["tools/build_identity.py"],CONFIG["build_identity"],"unchanged actual build identity")
need(identity_raw==prior_source["tools/build_identity.py"],"compiler source-map algorithm unchanged")
identity_ns={"__name__":"hepta_exact_core_source_identity","__file__":str(PRIOR/"source/tools/build_identity.py")}
exec(compile(identity_raw,identity_ns["__file__"],"exec"),identity_ns)
prior_compiler_inputs=identity_ns["source_inputs"](PRIOR/"source")
checked(encoded(prior_compiler_inputs),CONFIG["prior_compiler_inputs"],"exact actual56r1 compiler inputs")
need(len(prior_compiler_inputs)==217
     and sum(row["path"].startswith("src/") and row["path"].endswith(".java") for row in prior_compiler_inputs)==115,
     "actual56r1 compiler source-map counts")
compiler_paths={row["path"] for row in prior_compiler_inputs}
need(CONFIG["new_paths"]==[],"the two repairs add no source or compiler-input paths")
expected_compiler_inputs=[{"path":name,"sha256":sha(before[name])} for name in sorted(compiler_paths,key=Path)]
checked(encoded(expected_compiler_inputs),CONFIG["compiler_inputs"],"full current compiler-input prediction")
need(len(expected_compiler_inputs)==CONFIG["compiler_input_count"]==217
     and sum(row["path"].startswith("src/") and row["path"].endswith(".java")
             for row in expected_compiler_inputs)==CONFIG["java_source_count"]==115,
     "current exact217/115 compiler source-map counts")
old_compiler={row["path"]:row["sha256"] for row in prior_compiler_inputs}
compiler_changed=[row["path"] for row in expected_compiler_inputs
                  if old_compiler.get(row["path"])!=row["sha256"]]
need(compiler_changed==["src/org/trillionnium/hepta/local/WebShoppingDomain.java"],
     "the only changed compiler input is the actual Shopping evidence producer")
runner_raw=checked(before[CONFIG["runner"]["path"]],CONFIG["runner"],"unchanged original core101 runner")
need(runner_raw==prior_source[CONFIG["runner"]["path"]]
     and b'"-Xlint:all","-Werror"' in runner_raw and b'"-Wall","-Wextra","-Werror"' in runner_raw,
     "old Java/C compiler strictness and runner retained")
need(before["tests/completion/run_host_tests.py"]==prior_source["tests/completion/run_host_tests.py"],
     "original18-stage nested completion runner retained")
expected_host_inputs=host_input_rows(before)
checked(encoded(expected_host_inputs),CONFIG["expected_host_inputs"],"full current419 host input prediction")
need(len(expected_host_inputs)==CONFIG["host_input_count"]==419
     and len(host_input_rows(prior_source))==419,"unchanged original runner input-set rules")
signed_raw=load_bound(CONFIG["prior_signed_result"]["path"],CONFIG["prior_signed_result"],original_facts)
signed=strict(signed_raw)
need(signed["schema"]=="hepta.isolated-v55-assembly.v1" and signed["all_pass"] is True
     and signed["source_commit"]==CONFIG["prior_source_commit"]
     and signed["source_file_count"]==594 and signed["host_check_records"]==101
     and signed["host_input_count"]==418
     and signed["source_inventory_sha256"]==CONFIG["historical55_inventory"]["sha256"]
     and signed["host_checks_sha256"]==CONFIG["historical55_host_checks"]["sha256"],
     "actual signed55 core101 provenance")
prior_host_raw=unchanged(prior_evidence["host-checks/HOST-CHECKS.json"])
prior_host=strict(prior_host_raw)
need(prior_host["source_inputs"]==host_input_rows(prior_source),
     "complete actual56r1 host input map equals its failed source tree")
historical_host_raw=load_bound(CONFIG["historical55_host_checks"]["path"],
                               CONFIG["historical55_host_checks"],original_facts)
historical_host=strict(historical_host_raw)
need(historical_host["schema"]=="hepta.host-checks.v3" and historical_host["all_pass"] is True
     and len(historical_host["checks"])==101
     and all(type(row["exit_code"]) is int and row["exit_code"]==0 for row in historical_host["checks"]),
     "actual signed55 original101 name and order baseline")
original_check_names=[row["name"] for row in historical_host["checks"]]
need(len(original_check_names)==len(set(original_check_names))==101
     and [row["name"] for row in prior_host["checks"]]==original_check_names[:58],
     "unique original101 order and unchanged actual56r1 prefix")
tools={}
for name in ("java","javac"):
    _,facts=read_regular(CONFIG[name]["path"],CONFIG[name])
    need(os.access(facts["path"],os.X_OK),"actual current JDK executable")
    tools[name]=facts;original_facts.append(facts)
env=dict(os.environ)
for name in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH","SOURCE_HEAD_SHA"):
    env.pop(name,None)
env.update(PYTHONDONTWRITEBYTECODE="1",JAVA_HOME=CONFIG["jdk"],
           PATH=CONFIG["jdk"]+"/bin:"+os.environ.get("PATH","/usr/bin:/bin"))
need(shutil.which("java",path=env["PATH"])==tools["java"]["path"]
     and shutil.which("javac",path=env["PATH"])==tools["javac"]["path"],"exact JDK command lookup")
cc_requested=shutil.which("cc",path=env["PATH"])
need(cc_requested is not None,"existing host C compiler required")
cc_real=Path(cc_requested).resolve(strict=True)
cc_raw,cc_facts=read_regular(cc_real)
need(sha(cc_raw)==CONFIG["cc_sha256"] and os.access(cc_real,os.X_OK),"same original host C compiler")
tools["cc"]={**cc_facts,"requested_path":cc_requested};original_facts.append(cc_facts)
python_real=Path(sys.executable).resolve(strict=True)
_,python_facts=read_regular(python_real)
need(os.access(python_real,os.X_OK),"current Python executable")
tools["python"]=python_facts;original_facts.append(python_facts)
started=time.time()
ROOT.mkdir(mode=0o700)  # FIRST MUTATION; outside the handler, never reuse an earlier result.
steps,written=[],[]
OUT=ROOT/"host-checks"
result={"schema":"hepta.main56-original-core101-host-stage.v1","revision":"actual56r1-two-repairs-successor-r2",
        "all_pass":False,"exit_code":1,"source_root":str(SOURCE),"source_file_count":CONFIG["source_file_count"],
        "source_inventory_sha256":CONFIG["inventory"]["sha256"],"source_candidate_git":CONFIG["aggregate"]["git_blob_sha"],
        "actual_unsigned_result":None,"unsigned_build_prerequisite_required":False,
        "source_materialized_here":True,"source_commit":None,"publication_pending":True,
        "base_source_commit":CONFIG["prior_source_commit"],"base_source_file_count":594,
        "prior_materialized_source_file_count":595,"prior_core_all_pass":False,"prior_core_exit_code":1,
        "prior_actual_host_check_count":58,
        "host_check_count":0,"host_input_count":None,"nested_completion_stage_count":0,
        "nested18_are_within_core101":True,"focused39_rerun":False,"identity10_rerun":False,
        "query40_rerun":False,"separate_web_80_43_13_rerun":False,
        "original_runner_sha256":sha(runner_raw),"tools":tools,"steps":steps,
        "android_compiled_here":False,"android_native_runtime_recompiled_here":False,
        "original_host_native_contracts_executed":False,
        "signed":False,"published":False,"phone_actions":0,"business_verified":False,
        "actual_flight_results_provider_ready":False,
        "started_epoch":started,"error":None,"originals_unchanged":False,
        "prior_core_result":CONFIG["prior_core_result"],"prior_source_aggregate":CONFIG["prior_aggregate"],
        "exact_changed_existing_paths":CONFIG["changed_existing_paths"],"exact_new_paths":CONFIG["new_paths"],
        "prior_core_evidence_unchanged":False,"prior_failed_runs_are_preserved_history":True,
        "compiler_source_equivalent_to_predecessor":False,
        "compiler_source_matches_current_final_inventory":False,
        "compiler_input_changed_paths":compiler_changed,
        "original_unsigned_source_map_does_not_match_successor":True,
        "new_same_source_android_build_required":True,"source_map_difference_requires_signer_sidecar":False}
try:
    written.append(write_new(ROOT/"stage.py",stage_raw))
    written.append(write_new(ROOT/"CONFIG.json",encoded(CONFIG)))
    written.append(write_new(ROOT/"AGGREGATE.json",aggregate_raw))
    written.append(write_new(ROOT/"PRIOR-AGGREGATE.json",prior_aggregate_raw))
    written.append(write_new(ROOT/"SOURCE-DELTA.json",DELTA_RAW))
    written.append(write_new(ROOT/"PRIOR-COMPILER-INPUTS.json",encoded(prior_compiler_inputs)))
    written.append(write_new(ROOT/"PRIOR-CORE-EVIDENCE.json",encoded(prior_evidence)))
    SOURCE.mkdir(mode=0o700)
    for name,raw in sorted(before.items(),key=lambda item:Path(item[0])):
        written.append(write_new(SOURCE/name,raw))
    materialized,before_facts=snapshot(SOURCE)
    need(materialized==before and len(materialized)==CONFIG["source_file_count"],"exact complete new source tree readback")
    source_blob_rows=[{"path":name,"bytes":len(raw),"sha256":sha(raw),"git_blob_sha":blob(raw)}
                      for name,raw in sorted(materialized.items(),key=lambda item:Path(item[0]))]
    source_blob_raw=checked(encoded(source_blob_rows),CONFIG["source_blob_map"],"complete actual595 Git blob map")
    source_blob_facts=write_new(ROOT/"SOURCE-BLOB-MAP.json",source_blob_raw);written.append(source_blob_facts)
    compiler_inputs=identity_ns["source_inputs"](SOURCE)
    need(compiler_inputs==expected_compiler_inputs,"actual materialized217 equals the current source map")
    checked(encoded(compiler_inputs),CONFIG["compiler_inputs"],"full current217 compiler-input identity")
    written.append(write_new(ROOT/"COMPILER-INPUTS.json",encoded(compiler_inputs)))
    result.update(source_blob_map=source_blob_facts,compiler_input_count=CONFIG["compiler_input_count"],java_source_count=CONFIG["java_source_count"],
                  compiler_source_matches_current_final_inventory=True)
    written.append(write_new(ROOT/"PRIOR-CORE-R1-HOST-CHECKS.json",prior_host_raw))
    written.append(write_new(ROOT/"HISTORICAL55-CORE101.json",historical_host_raw))
    written.append(write_new(ROOT/"SOURCE-INVENTORY.json",inventory_raw))
    written.append(write_new(ROOT/"EXPECTED-HOST-INPUTS.json",encoded(expected_host_inputs)))
    (ROOT/"tmp").mkdir(mode=0o700)
    env["TMPDIR"]=str(ROOT/"tmp")
    argv=[sys.executable,"-B",SOURCE/CONFIG["runner"]["path"],"--out",OUT]
    written.append(write_new(ROOT/"START-ARGS.json",encoded({
        "host":"pocket4","key":CONFIG["key"],"argv":[str(x) for x in argv],"cwd":str(SOURCE),
        "java_home":CONFIG["jdk"],"source_inventory_sha256":CONFIG["inventory"]["sha256"],
        "source_file_count":CONFIG["source_file_count"],"timeout_seconds":CONFIG["timeout_seconds"],
        "source_modified":False,"source_materialized_new_here":True,
        "android_compile_prerequisite":False,"phone_actions":0})))
    run_step("original-host-checks",argv,CONFIG["timeout_seconds"],SOURCE,env)
    host_raw,host_facts=read_regular(OUT/"HOST-CHECKS.json")
    host=strict(host_raw);written.append(host_facts)
    checks=host.get("checks")
    need(host["schema"]=="hepta.host-checks.v3" and host["all_pass"] is True
         and type(checks) is list and len(checks)==101
         and all(type(row["exit_code"]) is int and row["exit_code"]==0 for row in checks),
         "all original101 host records must actually pass")
    need(host["android_compiled"] is False and host["phone_tested"] is False
         and host["native_grammar_model_tested"] is False and host["external_model_used"] is False,
         "original host-only scope retained")
    need(len({row["name"] for row in checks})==101
         and [row["name"] for row in checks]==original_check_names,"exact original101 names and order")
    need(host["source_inputs"]==expected_host_inputs,"actual full419 host input map equals fresh source")
    for row in checks:
        name=relative(row["name"]);need("/" not in name,"simple original check name")
        for suffix in ("stdout","stderr"):
            raw,facts=read_regular(OUT/(name+"."+suffix))
            need(sha(raw)==row[suffix+"_sha256"],"actual full original log "+name+"."+suffix)
            written.append(facts)
    nested_raw,nested_facts=read_regular(OUT/"task-completion/RESULT.json")
    nested=strict(nested_raw);written.append(nested_facts)
    need(nested["schema"]=="hepta.task-completion-host.v1" and nested["passed"] is True
         and [row["name"] for row in nested["stages"]]==CONFIG["nested_completion_stages"]
         and all(type(row["exit_code"]) is int and row["exit_code"]==0 for row in nested["stages"])
         and nested["compiler_contract"]=="Java 8 API release",
         "all original18 nested controller stages")
    result.update(host_checks=host_facts,host_check_count=101,host_input_count=len(host["source_inputs"]),
        nested_completion=nested_facts,nested_completion_stage_count=18,
        original_runner_unmodified=True,original101_names_order_preserved=True,
        reviewed_source_and_test_successor_exact=True,java8_api_release=True,
        original_host_native_contracts_executed=True,
        all_pass=True,exit_code=0)
except BaseException as failure:
    result["all_pass"]=False;result["exit_code"]=1
    result["error"]=type(failure).__name__+": "+str(failure)
    try:write_new(ROOT/"ERROR.txt",traceback.format_exc().encode("utf-8"))
    except Exception as logging_failure:
        result["error_record_failure"]=type(logging_failure).__name__+": "+str(logging_failure)
finally:
    # Preserve an actual partial or failed child report; never replace it with a synthetic pass.
    try:
        nested_path=OUT/"task-completion/RESULT.json"
        if nested_path.exists():
            raw,facts=read_regular(nested_path);actual_nested=strict(raw)
            actual_stages=[{"name":row["name"],"exit_code":row["exit_code"]} for row in actual_nested.get("stages",[])]
            result["actual_nested_result"]=facts;result["actual_nested_passed"]=actual_nested.get("passed")
            result["actual_nested_stages"]=actual_stages;result["actual_nested_stage_count"]=len(actual_stages)
            result["actual_nested_first_failure"]=next((row["name"] for row in actual_stages if row["exit_code"]!=0),None)
    except BaseException as evidence_failure:
        result["all_pass"]=False;result["exit_code"]=1
        result["nested_report_error"]=type(evidence_failure).__name__+": "+str(evidence_failure)
    host_path=OUT/"HOST-CHECKS.json"
    try:
        if host_path.exists():
            raw,facts=read_regular(host_path);actual=strict(raw)
            result["host_checks"]=facts
            result["actual_host_all_pass"]=actual.get("all_pass")
            result["actual_host_error"]=actual.get("error")
            result["host_check_count"]=len(actual.get("checks",[]))
            result["host_input_count"]=len(actual.get("source_inputs",[]))
    except BaseException as evidence_failure:
        result["all_pass"]=False;result["exit_code"]=1
        result["host_report_error"]=type(evidence_failure).__name__+": "+str(evidence_failure)
    try:
        for facts in original_facts:unchanged(facts)
        for facts in written:unchanged(facts)
        for step in steps:
            unchanged(step["stdout"]);unchanged(step["stderr"])
        after,after_facts=snapshot(SOURCE)
        need(before_facts is not None and after==before and after_facts==before_facts,
             "complete materialized595 source bytes and identities unchanged")
        prior_after,prior_after_facts=snapshot(PRIOR/"source")
        need(prior_after==prior_source and prior_after_facts==prior_source_facts,
             "complete actual56r1 source bytes and identities unchanged")
        need(identity_ns["source_inputs"](SOURCE)==expected_compiler_inputs,
             "final217 current compiler-input identity remains unchanged")
        need(identity_ns["source_inputs"](PRIOR/"source")==prior_compiler_inputs,
             "original217 actual56r1 compiler-input identity remains unchanged")
        result["prior_core_evidence_unchanged"]=True
        result["prior_core_guarded_file_count"]=len(prior_evidence)
        result["prior_source_unchanged"]=True
        result["originals_unchanged"]=True
        result["source_unchanged"]=True
        result["base_source_unchanged"]=True
        result["written_files_unchanged"]=True
    except BaseException as integrity_failure:
        result["all_pass"]=False;result["exit_code"]=1
        result["integrity_error"]=type(integrity_failure).__name__+": "+str(integrity_failure)
    result["finished_epoch"]=time.time()
    result["elapsed_seconds"]=result["finished_epoch"]-started
    result["stage_sha256"]=sha(stage_raw)
    result["original_guard_count"]=len(original_facts)
    result["written_guard_count"]=len(written)
    result["all_pass"]=bool(result["all_pass"] and result["originals_unchanged"])
    result["exit_code"]=0 if result["all_pass"] else 1
    result_facts=write_new(ROOT/"RESULT.json",encoded(result))
    summary={"schema":"hepta.main56-original-core101-host-summary.v1",
        "all_pass":result["all_pass"],"exit_code":result["exit_code"],"result":result_facts,
        "error":result.get("error"),"actual_host_error":result.get("actual_host_error"),
        "source_file_count":CONFIG["source_file_count"],"source_inventory_sha256":CONFIG["inventory"]["sha256"],
        "host_check_count":result["host_check_count"],"host_input_count":result["host_input_count"],
        "nested_completion_stage_count":result["nested_completion_stage_count"],
        "actual_nested_stage_count":result.get("actual_nested_stage_count"),
        "actual_nested_first_failure":result.get("actual_nested_first_failure"),
        "prior_core_evidence_unchanged":result["prior_core_evidence_unchanged"],
        "compiler_source_equivalent_to_predecessor":result["compiler_source_equivalent_to_predecessor"],
        "compiler_source_matches_current_final_inventory":result["compiler_source_matches_current_final_inventory"],
        "compiler_input_changed_paths":result["compiler_input_changed_paths"],
        "new_same_source_android_build_required":True,
        "nested18_are_within_core101":True,"phone_actions":0,"signed":False,
        "focused39_rerun":False,"query40_rerun":False,"separate_web_80_43_13_rerun":False}
    write_new(ROOT/"SUMMARY.json",encoded(summary))
    print(json.dumps(summary,sort_keys=True,ensure_ascii=False,allow_nan=False),flush=True)
raise SystemExit(result["exit_code"])
