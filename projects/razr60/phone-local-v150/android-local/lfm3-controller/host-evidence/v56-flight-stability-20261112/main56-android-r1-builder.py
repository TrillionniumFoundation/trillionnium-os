#!/usr/bin/env python3
"""Build a sealed main56 source successor on Pocket4 and reuse signed54 native payloads exactly.
No native compiler, signer, publication, download, ADB or phone action is executed.
"""
import gzip, hashlib, io, json, os, re, signal, stat, struct, subprocess, sys, tarfile, time, traceback, zipfile
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

CONFIG = json.loads("{\"schema\":\"hepta.main56-pocket4-java-native-reuse-config.v1\",\"root\":\"/home/alex/hepta-local-007f-20261111/v56-main-p4-android-r1\",\"base_root\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4\",\"aggregate\":{\"git\":\"0803dec4b6acc359b810bb79ca6fdd01ada69a8c\",\"bytes\":1427055,\"sha256\":\"c1cc7cc16eef4c3a34131ee719101a69db080b76e72c98f03248036fc6fd628f\"},\"decoded_input\":{\"bytes\":1564155,\"sha256\":\"1ef8ac7725aa8ed15ac628e6471b4469a75784f2050fdb442443f065fb132459\"},\"source_file_count\":595,\"overlay_file_count\":40,\"compiler_input_count\":217,\"java_source_count\":115,\"source_inventory_sha256\":\"ca24673843908c7f9343c949af64b8393e69ce53605128782036ae9ce9d1f46e\",\"base_source_commit\":\"42d3a0f447807659c0f78c8273edee01dd1b734f\",\"base_source_inventory_sha256\":\"8675c0c438cdf10f599c23a3a6305a5678fd59270f09b4f73a43f7a67bf2237d\",\"base_signed_result\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/assembly-r1/RESULT.json\",\"bytes\":15659,\"sha256\":\"eadc9dbb63b411015571a488377be6a8704c9f78415169a5164c8f13571f0f72\"},\"base_apk\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/out/hepta-local-0.54.0.apk\",\"bytes\":20985685,\"sha256\":\"0729f54704a058049e12041c7f901b1b6650924500663cf9952a03d6a33a8b8a\"},\"base_archive\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/mac-artifacts.tar.gz\",\"bytes\":562137,\"sha256\":\"17da0d3a86bd8505daa07e9895643b7de2d2877768fbaf9c8abd8475f8c6bcc2\"},\"base_mac_stage\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/release-evidence-r1/MAC-STAGE-ORIGINAL.json\",\"bytes\":28841,\"sha256\":\"a037b49f05ea48caccb2902b95bbb2314a5f767e230138dd14ae3a16851ee4b2\"},\"base_compiler\":{\"bytes\":42341,\"sha256\":\"51265398de2dcc4ccefb5aa0e24ea91770d8c9f3b54248f3d88068e04a4436cc\"},\"base_build_stdout\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/release-evidence-r1/mac/original-android-native-build.stdout\",\"bytes\":121423,\"sha256\":\"ce47720cad1c09c685657b0d0c801281552cc69a0d15679cb5ffd24ec992e422\"},\"worker\":{\"bytes\":59952,\"sha256\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\"},\"generated_worker_sha256\":\"77b914eae46ea000d3c955628c35f6e96a715a4a14da3eb075923d2e6024bbb0\",\"native_pins\":{\"libMNN.so\":\"5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d\",\"libc++_shared.so\":\"77a34d3f03b17709f3f6473f37cb7795314e51fa3e5e652b5c37d53cfd05c754\",\"libgeniex.so\":\"99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56\",\"libgeniex_plugin_llama_cpp.so\":\"cc186649cc0dab10240395f89d14d007e62b3bc78283060027d37ee80a21604a\",\"libggml-base.so\":\"bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40\",\"libggml-cpu.so\":\"b603d578bb3beb0c3727be748f327c002619827df701bf0b894632272670943b\",\"libggml-hexagon.so\":\"67b886eb9bcdd298268a8463d74f07da4213024fe7ed89911c2e76c9e0d1491f\",\"libggml-htp-v79.so\":\"110d9e6ff7cff02fa73b0a3c03d8259222758934bdbcae5c819dae6729f362d5\",\"libggml-opencl.so\":\"e395cf83e695aa9d21dd90a89460f936742c7c8c706cfbbdfa647dd316dd0875\",\"libggml.so\":\"5dff1d15e528d1accb1704a1049a6556784cbfc32131fb64cef5c8847c171149\",\"libhepta_local_runner.so\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"libhepta_mobimind_runner.so\":\"b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020\",\"libhepta_ui_venus_runner.so\":\"5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551\",\"libllama-common.so\":\"8b05589a739339dd38ad524e9733d89650ef40b0a83fe3a95ff83716c98c6122\",\"libllama.so\":\"4bb7bd0f4fe0bd24ac32a80f920838fd2f525430ad58c5d5742cc745f7d0b835\",\"libmtmd.so\":\"ccf32e264cdccc6378d5e4e005f4aedae39eb3e9a198550c5f7f3a4583bcaa4d\",\"libomp.so\":\"b0b507bb9e89360304272ba335d5fb2f6661f88842c2b3c749474cb7b8acda76\"},\"identity_root\":\"/home/alex/hepta-local-007f-20261111/v55-installed-apk-identity-host-r1\",\"identity_result\":{\"bytes\":5727,\"sha256\":\"52762ada64c63bc58749d62e9bd183b586c40349f0e10082ded1c308d82df4f7\"},\"identity_stage\":{\"bytes\":14247,\"sha256\":\"17f95a5eecf3716c48228c4086e2d428b4e5c2c57c77707116673d92820d9bf8\"},\"identity_input\":{\"bytes\":36100,\"sha256\":\"bfcee1680b7e3c4c0933aed26bfce6320b64ae7803347f3ddfc56616067b8176\"},\"identity_source\":{\"bytes\":9255,\"sha256\":\"e3ca49ba910ff1bb26f50452e1f718313dbce51df9d77c8b107867351178e1d9\"},\"identity_generated\":{\"bytes\":14192,\"sha256\":\"38ec317c6344665e06c73c3c50816cbfa4e96ef3ed69b6a40dd38d525ca26dd7\"},\"focused_root\":\"/home/alex/hepta-local-007f-20261111/v56-main-wire4-host-p4-r1\",\"focused_result\":{\"bytes\":44408,\"sha256\":\"036e4f7b185a127e457712fcd23b6745d8aac18a04cf64da4035764329efee43\"},\"focused_input\":{\"bytes\":1283344,\"sha256\":\"25b80314fb000cf4e48a56ad4e198d6b2fb0917802e1f687c5d041f17e04a13b\"},\"focused_stage\":{\"bytes\":69343,\"sha256\":\"eaf4de0485e4990ec56751e55b1efdca4492f7b75b9507e2ca409db87fcbb9bd\"},\"calendar_dom\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/release-evidence-r1/fixtures/calendar-stable.json\",\"bytes\":386724,\"sha256\":\"f61fd86cb24b212c3434bb5eda1a4e29b65c06c22d3fc4238366f31a324dd7fa\"},\"calendar_ax\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/release-evidence-r1/fixtures/calendar-stable.xml\",\"bytes\":178888,\"sha256\":\"59d753e32edd620eb2e1fb0947c898df89eb7bf8dbc63dc4138a1636272b82ec\"},\"query_runner\":{\"bytes\":41005,\"sha256\":\"5af6324496884603f2be5184334335e17d59dd653d0dd20ec859d5c064820b10\"},\"jdk\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64\",\"tools\":{\"java\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/java\",\"bytes\":14544,\"sha256\":\"bb70208200cb6538b877d80478141194a716edb591f4910ec106589291e99196\"},\"javac\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/javac\",\"bytes\":14592,\"sha256\":\"2aaf03d13aeb80b8269696f2dcd9f4937d7366bbc68f91fdc703cf157e8f39c4\"},\"json\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-public-inputs-r1/host-json/json-20240303.jar\",\"bytes\":78332,\"sha256\":\"3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed\"},\"android_jar\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-sdk-input-r2/sdk/android-34/android.jar\",\"bytes\":26361808,\"sha256\":\"6cea1df3efb77103ac3e2beb9bf4718964b0e0869ab16d39d29d5cbae1c147ad\"},\"r8\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-public-large-inputs-r1/tools/r8-8.13.17.jar\",\"bytes\":18279079,\"sha256\":\"d31fd0dc751d48740009cdd9a485126acb1d0d14c59b9f05579479940f4adf74\"},\"aapt2\":{\"path\":\"/usr/lib/android-sdk/build-tools/debian/aapt2\",\"bytes\":54512,\"sha256\":\"0e9ff92342040acdfd03e8708512f4e02353e3ca0a2b85ea2950da659110b009\"}},\"sdk_download_root\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-sdk-input-r2\",\"sdk_download_result\":{\"bytes\":64222,\"sha256\":\"5300257b246f73bc410028d8e1e61f18381e6f9b4a4406661d00b7d3d128eab6\"},\"original_aggregate\":{\"git\":\"d3bf59d91e5681fd5991c4bfef8587ba9a7b2a2d\",\"bytes\":1320157,\"sha256\":\"66ac069a14b64db51d9f2d09bf52acc6a8d9dc93484f8c21e3c3276ac31c2f06\"},\"original_decoded_input\":{\"bytes\":1451937,\"sha256\":\"0e9a2e1a8e485c4cbc5d03e12ee4a405f6b6d3e8db3dff431dc27f9abcc98edb\"},\"original_source_inventory_sha256\":\"65bf7934d82692f45c10aedb947613043453b30bc7d55c4dc8b7e44e4ca0bed1\",\"materialized_root\":\"/home/alex/hepta-local-007f-20261111/v56-main-core101-materialized-host-r2\",\"prior_build_root\":\"/home/alex/hepta-local-007f-20261111/v55-main-p4-android-r2\",\"prior_build_result\":{\"bytes\":199633,\"sha256\":\"267272033459763c9542b98a701048bfd09cf120510e79aa2c5be4ee5b3f6db7\"},\"prior_build_stage\":{\"bytes\":74743,\"sha256\":\"caaf8785217656d251d5acd571184925ba41b0da3b250bb22dfa55d1e4470114\",\"git_blob_sha\":\"7433e0f8f636653e245dc5ebd26c23f912c0ec81\"},\"prior_compiler_inputs\":{\"bytes\":34208,\"sha256\":\"cf9549832cfdf97be65866600fb0021fb53ab11851c4b490ea07b80ff9265db9\"},\"compiler_inputs\":{\"bytes\":34376,\"sha256\":\"2b9e1d971a60d09df7303f050cef40d4b254b016a6f68c272035ec11ef854071\"},\"source_deltas\":[{\"path\":\"AndroidManifest.xml\",\"base\":{\"bytes\":2585,\"sha256\":\"57502c24cd050f5468de3c9e1af130a3af3d34ac8a4d40553d35f86dfad8e8d7\",\"git_blob_sha\":\"d0aa04d57d2e2902f55331156bbb6261fd4b6d59\"},\"candidate\":{\"bytes\":2582,\"sha256\":\"c372aebecde61283232394ea687045992c68b689ab954ad523bc5569f96389bc\",\"git_blob_sha\":\"24d84378527e48f8090129609da7f8e66f362b45\"},\"ordered_patches\":[{\"before\":\"android:versionCode=\\\"55\\\"\",\"after\":\"android:versionCode=\\\"56\\\"\",\"count\":1},{\"before\":\"android:versionName=\\\"0.55.0-scoped-official-web\\\"\",\"after\":\"android:versionName=\\\"0.56.0-flight-stability\\\"\",\"count\":1}]},{\"path\":\"src/org/trillionnium/hepta/local/HeptaAccessibilityService.java\",\"base\":{\"bytes\":117505,\"sha256\":\"cfd95f10db8b3c2a34830a73875c2e1bfaa1a6b6fdca47bc20be346ed77104fd\",\"git_blob_sha\":\"effb13c0668fcef5499502876fa0277bf99c83c6\"},\"candidate\":{\"bytes\":129287,\"sha256\":\"53dc2765f2f0504a4ea16618a2e0b44c0d443dceeb3834f030098ae2cea26fba\",\"git_blob_sha\":\"6200e5325ec1397abd73e9bfa99235c7b063935d\"},\"ordered_patches\":[{\"before\":\"    public interface ObservationCallback { void onObservation(PhoneObservation value); void onError(String error); }\",\"after\":\"    /** Only the service may construct this token from a live graph and original NodeRef. */\\n    static final class FlightNativeCheck {\\n        private final PhoneObservation frame;private final WebFlightNativeStability.Permit permit;\\n        final long checkedAt;private final String raw;\\n        private FlightNativeCheck(PhoneObservation frame,WebFlightNativeStability.Permit permit,\\n                                  long started,long ended,JSONObject nativeProof,JSONObject windows,\\n                                  boolean originalDigestEqual)throws Exception{\\n            this.frame=frame;this.permit=permit;checkedAt=ended;\\n            raw=org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(new JSONObject()\\n                    .put(\\\"schema\\\",\\\"hepta.flight-home-live-native-stability.v1\\\").put(\\\"task_id\\\",permit.taskId)\\n                    .put(\\\"model_run_id\\\",permit.run).put(\\\"observation_id\\\",frame.id)\\n                    .put(\\\"original_observation_state_sha256\\\",frame.treeSha256)\\n                    .put(\\\"binding_sha256\\\",permit.bindingSha).put(\\\"webview_instance\\\",permit.instance)\\n                    .put(\\\"navigation_epoch\\\",permit.epoch).put(\\\"display_id\\\",permit.displayId).put(\\\"window_id\\\",permit.windowId)\\n                    .put(\\\"started_elapsed_ms\\\",started).put(\\\"checked_elapsed_ms\\\",ended)\\n                    .put(\\\"original_global_digest_equal\\\",originalDigestEqual).put(\\\"scope_is_compiled_home_booking_only\\\",true)\\n                    .put(\\\"dom\\\",permit.domEvidence()).put(\\\"native\\\",nativeProof).put(\\\"interactive_windows\\\",windows)\\n                    .put(\\\"original_node_ref_identity_preserved\\\",true).put(\\\"actual_ancestor_chain_refreshed\\\",true)\\n                    .put(\\\"two_interactive_window_reads_equal\\\",true).put(\\\"ime_hidden\\\",true)\\n                    .put(\\\"coordinates_used_for_input\\\",false).put(\\\"fully_unoccluded_claimed\\\",false)\\n                    .put(\\\"native_invocation_entered\\\",false).put(\\\"business_verified\\\",false));\\n        }\\n        boolean matches(PhoneObservation frame,WebFlightNativeStability.Permit permit){return this.frame==frame&&this.permit==permit;}\\n        JSONObject evidence()throws Exception{return new JSONObject(raw);}\\n    }\\n    public interface ObservationCallback { void onObservation(PhoneObservation value); void onError(String error); }\",\"count\":1},{\"before\":\"            if(ActionPolicy.requiresStableTree(action)&&!currentGraph.digest.equals(now.digest))\\n                return \\\"stale:目标窗口内容已变化\\\";\",\"after\":\"            if(ActionPolicy.requiresStableTree(action)){\\n                WebFlightSession web=taskWeb;\\n                WebFlightNativeStability.Permit permit=web==null?null:web.flightNativePermitForDispatch(action,expected);\\n                if(permit!=null){\\n                    try{web.acceptFlightNativeCheck(action,expected,\\n                            requireLiveFlightNativeStability(taskId,expected,action,permit,now,cancel));}\\n                    catch(Exception mismatch){throw new StaleObservation(\\\"stale:首页目标局部复核失败：\\\"+message(mismatch));}\\n                }else if(!currentGraph.digest.equals(now.digest))return \\\"stale:目标窗口内容已变化\\\";\\n            }\",\"count\":1},{\"before\":\"        final Map<String,NodeRef> refs=new HashMap<String,NodeRef>();\",\"after\":\"        final Map<String,NodeRef> refs=new HashMap<String,NodeRef>();\\n        JSONArray flightNativeSnapshot;boolean flightNativeSnapshotComplete;\",\"count\":1},{\"before\":\"        Graph graph=new Graph();graph.displayId=background==null?Display.DEFAULT_DISPLAY:background.displayId();\",\"after\":\"        Graph graph=new Graph();graph.displayId=background==null?Display.DEFAULT_DISPLAY:background.displayId();\\n        if(webEvidence&&activeWeb.goal!=null){graph.flightNativeSnapshot=new JSONArray();graph.flightNativeSnapshotComplete=true;}\",\"count\":1},{\"before\":\"                    int actualChildren=node.getChildCount();\\n                    int children=Math.min(actualChildren,MAX_VISITED-visited-queue.size());\",\"after\":\"                    int actualChildren=node.getChildCount();\\n                    if(graph.flightNativeSnapshot!=null&&graph.flightNativeSnapshotComplete){\\n                        try{\\n                            if(graph.flightNativeSnapshot.length()>=WebFlightNativeStability.MAX_NATIVE_NODES)\\n                                throw new IllegalStateException(\\\"bounded full Flight snapshot exceeded\\\");\\n                            graph.flightNativeSnapshot.put(snapshotFlightNode(node,nativePath,nativeParentClass));\\n                        }catch(Exception unavailable){graph.flightNativeSnapshotComplete=false;}\\n                    }\\n                    int children=Math.min(actualChildren,MAX_VISITED-visited-queue.size());\",\"count\":1},{\"before\":\"    private static String nodeSignature(AccessibilityNodeInfo node,ObservedChildText.Result childText){\",\"after\":\"    private static JSONObject snapshotFlightNode(AccessibilityNodeInfo node,String path,String parentClass)throws Exception{\\n        String text=node.isPassword()?\\\"\\\":string(node.getText()),description=node.isPassword()?\\\"\\\":string(node.getContentDescription());\\n        if(path==null||path.isEmpty()||path.length()>240||text.length()>1024||description.length()>1024\\n                ||string(node.getViewIdResourceName()).length()>256||string(node.getClassName()).length()>128)\\n            throw new IllegalStateException(\\\"complete bounded Flight node fields unavailable\\\");\\n        Rect r=new Rect();node.getBoundsInScreen(r);\\n        return new JSONObject().put(\\\"path\\\",path).put(\\\"parent_class\\\",parentClass)\\n                .put(\\\"package\\\",string(node.getPackageName())).put(\\\"window_id\\\",node.getWindowId())\\n                .put(\\\"class\\\",string(node.getClassName())).put(\\\"view_id\\\",string(node.getViewIdResourceName()))\\n                .put(\\\"text\\\",text).put(\\\"description\\\",description)\\n                .put(\\\"bounds\\\",new JSONArray(new int[]{r.left,r.top,r.right,r.bottom}))\\n                .put(\\\"visible\\\",node.isVisibleToUser()&&!r.isEmpty()).put(\\\"enabled\\\",node.isEnabled())\\n                .put(\\\"clickable\\\",node.isClickable()).put(\\\"editable\\\",node.isEditable()).put(\\\"scrollable\\\",node.isScrollable())\\n                .put(\\\"focused\\\",node.isFocused()).put(\\\"password\\\",node.isPassword()).put(\\\"children\\\",node.getChildCount())\\n                .put(\\\"scroll_actions\\\",readScrollActions(node).fingerprintInput())\\n                .put(\\\"ime_enter\\\",readImeEnter(node).fingerprintInput())\\n                .put(\\\"input_sha256\\\",inputTextHash(node)==null?JSONObject.NULL:inputTextHash(node));\\n    }\\n    private FlightNativeCheck requireLiveFlightNativeStability(String taskId,PhoneObservation frame,ActionDecision action,\\n            WebFlightNativeStability.Permit permit,Graph now,Cancellation cancel)throws Exception{\\n        long started=SystemClock.elapsedRealtime();BackgroundSession background=backgroundFor(taskId);Graph before=currentGraph;\\n        if(background==null||before==null||frame!=current||cancel.isCancelled()||!owns(taskId)\\n                ||before.truncated||now.truncated||before.collectionStats==null||now.collectionStats==null\\n                ||before.collectionStats.truncated()||now.collectionStats.truncated()\\n                ||!before.flightNativeSnapshotComplete||!now.flightNativeSnapshotComplete\\n                ||before.flightNativeSnapshot==null||now.flightNativeSnapshot==null\\n                ||before.flightNativeSnapshot.length()!=before.collectionStats.visited\\n                ||now.flightNativeSnapshot.length()!=now.collectionStats.visited\\n                ||before.state.imeVisibility!=ImeVisibility.HIDDEN||now.state.imeVisibility!=ImeVisibility.HIDDEN\\n                ||!before.windowMetadata.bindFreshness(\\\"\\\").equals(now.windowMetadata.bindFreshness(\\\"\\\")))\\n            throw new StaleObservation(\\\"完整原生树、输入法或窗口元数据不可证明\\\");\\n        background.requireActive();\\n        NodeRef original=before.refs.get(action.nodeId),fresh=null;\\n        for(PhoneObservation.Node row:now.rows)if(permit.targetPath.equals(row.nativeTreePath)){\\n            if(fresh!=null)throw new StaleObservation(\\\"原生目标路径不唯一\\\");fresh=now.refs.get(row.id);\\n        }\\n        if(original==null||fresh==null||!original.node.equals(fresh.node)||!original.signature.equals(fresh.signature))\\n            throw new StaleObservation(\\\"原始节点引用与同路径新目标不相同\\\");\\n        JSONObject proof=WebFlightNativeStability.compareNative(before.flightNativeSnapshot,now.flightNativeSnapshot,permit.targetPath);\\n        JSONArray oldRetained=new JSONArray(),newRetained=new JSONArray();\\n        for(PhoneObservation.Node row:before.rows)oldRetained.put(row.json());\\n        for(PhoneObservation.Node row:now.rows)newRetained.put(row.json());\\n        proof.put(\\\"retained_node_pairing\\\",WebFlightNativeStability.compareRetained(oldRetained,newRetained,\\n                proof.getString(\\\"native_slider_path\\\")));\\n        JSONObject windowsBefore=readRegionWindows(frame,permit.displayId,permit.windowId,permit.bounds());\\n        refreshFlightTargetChain(background,frame,original,permit.targetPath,before.flightNativeSnapshot);\\n        if(!original.signature.equals(nodeSignature(original.node,observedChildText(original.node,true))))\\n            throw new StaleObservation(\\\"原始目标最后签名已变化\\\");\\n        JSONObject windowsAfter=readRegionWindows(frame,permit.displayId,permit.windowId,permit.bounds());\\n        if(!org.trillionnium.hepta.webprotocol.WebDomCanonical.same(windowsBefore,windowsAfter))\\n            throw new StaleObservation(\\\"首页点击前窗口覆盖关系已变化\\\");\\n        background.requireActive();\\n        if(cancel.isCancelled()||!owns(taskId)||frame!=current)throw new StaleObservation(\\\"首页任务已退休\\\");\\n        return new FlightNativeCheck(frame,permit,started,SystemClock.elapsedRealtime(),proof,windowsAfter,before.digest.equals(now.digest));\\n    }\\n    private void refreshFlightTargetChain(BackgroundSession background,PhoneObservation frame,NodeRef original,\\n                                         String targetPath,JSONArray snapshot)throws Exception{\\n        java.util.Map<String,JSONObject> records=new java.util.HashMap<String,JSONObject>();\\n        for(int i=0;i<snapshot.length();i++){JSONObject row=snapshot.getJSONObject(i);records.put(row.getString(\\\"path\\\"),row);}\\n        java.util.List<AccessibilityNodeInfo> owned=new java.util.ArrayList<AccessibilityNodeInfo>();\\n        AccessibilityNodeInfo cursor=original.node;String path=targetPath;\\n        Rect target=new Rect();cursor.getBoundsInScreen(target);\\n        try{\\n            for(int depth=0;depth<64;depth++){\\n                JSONObject expected=records.get(path);\\n                if(expected==null||!cursor.refresh()||!cursor.isVisibleToUser()||!cursor.isEnabled()||cursor.isPassword())\\n                    throw new StaleObservation(\\\"首页目标祖先不可用\\\");\\n                requireBackgroundNodeWindow(background,frame,cursor);\\n                Rect actual=new Rect();cursor.getBoundsInScreen(actual);\\n                if(!actual.contains(target)||!org.trillionnium.hepta.webprotocol.WebDomCanonical.same(expected,\\n                        snapshotFlightNode(cursor,path,expected.getString(\\\"parent_class\\\"))))\\n                    throw new StaleObservation(\\\"首页目标祖先或原生几何已变化\\\");\\n                AccessibilityNodeInfo parent=cursor.getParent();if(parent!=null)owned.add(parent);\\n                if(\\\"0\\\".equals(path)){\\n                    if(parent!=null)throw new StaleObservation(\\\"首页原生根边界变化\\\");return;\\n                }\\n                int slash=path.lastIndexOf('/'),index=Integer.parseInt(path.substring(slash+1));\\n                if(parent==null||!parent.refresh()||index>=parent.getChildCount()\\n                        ||!expected.getString(\\\"parent_class\\\").equals(string(parent.getClassName())))\\n                    throw new StaleObservation(\\\"首页目标父节点关系变化\\\");\\n                AccessibilityNodeInfo child=parent.getChild(index);if(child!=null)owned.add(child);\\n                if(child==null||!child.refresh()||!child.equals(cursor))throw new StaleObservation(\\\"首页目标父子身份变化\\\");\\n                cursor=parent;path=path.substring(0,slash);\\n            }\\n            throw new StaleObservation(\\\"首页原生祖先预算不足\\\");\\n        }finally{for(AccessibilityNodeInfo node:owned)node.recycle();}\\n    }\\n    private static String nodeSignature(AccessibilityNodeInfo node,ObservedChildText.Result childText){\",\"count\":1},{\"before\":\"    private JSONObject readRegionWindows(PhoneObservation frame,WebRegionNativeBridge bridge)throws Exception{\\n        AccessibilityServiceInfo info=getServiceInfo();\\n        if(info==null||(info.flags&AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS)==0\\n                ||(info.getCapabilities()&AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT)==0)\\n            throw new StaleObservation(\\\"原生窗口覆盖元数据不可用\\\");\\n        List<AccessibilityWindowInfo> windows=windowsForDisplay(bridge.displayId);\\n        if(windows==null)throw new StaleObservation(\\\"原生窗口集合不可用\\\");\\n        try{\\n            if(windows.isEmpty()||windows.size()>64)throw new StaleObservation(\\\"原生窗口集合不可用\\\");\\n            java.util.TreeMap<Integer,JSONObject> rows=new java.util.TreeMap<Integer,JSONObject>();\\n            int targetLayer=-1;Rect targetBounds=null;\\n            for(AccessibilityWindowInfo window:windows){\\n                if(window==null||window.getDisplayId()!=bridge.displayId||window.getId()<0\\n                        ||window.getType()<=0||window.getLayer()<0)\\n                    throw new StaleObservation(\\\"原生窗口身份缺失\\\");\\n                Rect bounds=new Rect();window.getBoundsInScreen(bounds);\\n                if(bounds.isEmpty())throw new StaleObservation(\\\"原生窗口范围未知\\\");\\n                JSONObject row=new JSONObject().put(\\\"window_id\\\",window.getId()).put(\\\"display_id\\\",window.getDisplayId())\\n                        .put(\\\"type\\\",window.getType()).put(\\\"layer\\\",window.getLayer())\\n                        .put(\\\"bounds\\\",new JSONArray(new int[]{bounds.left,bounds.top,bounds.right,bounds.bottom}))\\n                        .put(\\\"focused\\\",window.isFocused()).put(\\\"active\\\",window.isActive());\\n                if(rows.put(window.getId(),row)!=null)throw new StaleObservation(\\\"原生窗口身份重复\\\");\\n                if(window.getId()==bridge.windowId){\\n                    if(window.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION)\\n                        throw new StaleObservation(\\\"目标已不是原应用窗口\\\");\\n                    targetLayer=window.getLayer();targetBounds=new Rect(bounds);\\n                }\\n                if(window.getType()==AccessibilityWindowInfo.TYPE_INPUT_METHOD)\\n                    throw new StaleObservation(\\\"商品只读点击时出现输入法窗口\\\");\\n            }\\n            int[] expected=frame.windowMetadata.windowBounds(),region=bridge.anchorBounds();\\n            Rect anchorBounds=new Rect(region[0],region[1],region[2],region[3]);\\n            if(targetLayer<0||targetBounds==null||expected==null||expected.length!=4\\n                    ||targetBounds.left!=expected[0]||targetBounds.top!=expected[1]\\n                    ||targetBounds.right!=expected[2]||targetBounds.bottom!=expected[3]||!targetBounds.contains(anchorBounds))\\n                throw new StaleObservation(\\\"目标原生窗口或卡片范围已变化\\\");\\n            for(AccessibilityWindowInfo window:windows)if(window.getId()!=bridge.windowId&&window.getLayer()>=targetLayer){\\n                Rect bounds=new Rect();window.getBoundsInScreen(bounds);\\n                if(Rect.intersects(bounds,anchorBounds))throw new StaleObservation(\\\"原生商品区域被其它交互窗口覆盖\\\");\\n            }\\n            JSONArray ordered=new JSONArray();for(JSONObject row:rows.values())ordered.put(row);\\n            return new JSONObject().put(\\\"source\\\",\\\"getWindowsOnAllDisplays_selected_display_metadata\\\")\\n                    .put(\\\"display_id\\\",bridge.displayId).put(\\\"target_window_id\\\",bridge.windowId).put(\\\"target_layer\\\",targetLayer)\\n                    .put(\\\"target_native_bounds\\\",new JSONArray(region)).put(\\\"windows\\\",ordered)\\n                    .put(\\\"observed_upper_or_same_layer_overlap\\\",false).put(\\\"ime_window_observed\\\",false)\\n                    .put(\\\"other_window_roots_traversed\\\",false).put(\\\"unreported_windows_excluded\\\",false);\\n        }finally{for(AccessibilityWindowInfo window:windows)if(window!=null)window.recycle();}\\n    }\\n\",\"after\":\"    private JSONObject readRegionWindows(PhoneObservation frame,WebRegionNativeBridge bridge)throws Exception{\\n        return readRegionWindows(frame,bridge.displayId,bridge.windowId,bridge.anchorBounds());\\n    }\\n    private JSONObject readRegionWindows(PhoneObservation frame,int displayId,int windowId,int[] region)throws Exception{\\n        AccessibilityServiceInfo info=getServiceInfo();\\n        if(info==null||(info.flags&AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS)==0\\n                ||(info.getCapabilities()&AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT)==0)\\n            throw new StaleObservation(\\\"原生窗口覆盖元数据不可用\\\");\\n        List<AccessibilityWindowInfo> windows=windowsForDisplay(displayId);\\n        if(windows==null)throw new StaleObservation(\\\"原生窗口集合不可用\\\");\\n        try{\\n            if(windows.isEmpty()||windows.size()>64)throw new StaleObservation(\\\"原生窗口集合不可用\\\");\\n            java.util.TreeMap<Integer,JSONObject> rows=new java.util.TreeMap<Integer,JSONObject>();\\n            int targetLayer=-1;Rect targetBounds=null;\\n            for(AccessibilityWindowInfo window:windows){\\n                if(window==null||window.getDisplayId()!=displayId||window.getId()<0\\n                        ||window.getType()<=0||window.getLayer()<0)\\n                    throw new StaleObservation(\\\"原生窗口身份缺失\\\");\\n                Rect bounds=new Rect();window.getBoundsInScreen(bounds);\\n                if(bounds.isEmpty())throw new StaleObservation(\\\"原生窗口范围未知\\\");\\n                JSONObject row=new JSONObject().put(\\\"window_id\\\",window.getId()).put(\\\"display_id\\\",window.getDisplayId())\\n                        .put(\\\"type\\\",window.getType()).put(\\\"layer\\\",window.getLayer())\\n                        .put(\\\"bounds\\\",new JSONArray(new int[]{bounds.left,bounds.top,bounds.right,bounds.bottom}))\\n                        .put(\\\"focused\\\",window.isFocused()).put(\\\"active\\\",window.isActive());\\n                if(rows.put(window.getId(),row)!=null)throw new StaleObservation(\\\"原生窗口身份重复\\\");\\n                if(window.getId()==windowId){\\n                    if(window.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION)\\n                        throw new StaleObservation(\\\"目标已不是原应用窗口\\\");\\n                    targetLayer=window.getLayer();targetBounds=new Rect(bounds);\\n                }\\n                if(window.getType()==AccessibilityWindowInfo.TYPE_INPUT_METHOD)\\n                    throw new StaleObservation(\\\"商品只读点击时出现输入法窗口\\\");\\n            }\\n            int[] expected=frame.windowMetadata.windowBounds();\\n            Rect anchorBounds=new Rect(region[0],region[1],region[2],region[3]);\\n            if(targetLayer<0||targetBounds==null||expected==null||expected.length!=4\\n                    ||targetBounds.left!=expected[0]||targetBounds.top!=expected[1]\\n                    ||targetBounds.right!=expected[2]||targetBounds.bottom!=expected[3]||!targetBounds.contains(anchorBounds))\\n                throw new StaleObservation(\\\"目标原生窗口或卡片范围已变化\\\");\\n            for(AccessibilityWindowInfo window:windows)if(window.getId()!=windowId&&window.getLayer()>=targetLayer){\\n                Rect bounds=new Rect();window.getBoundsInScreen(bounds);\\n                if(Rect.intersects(bounds,anchorBounds))throw new StaleObservation(\\\"原生商品区域被其它交互窗口覆盖\\\");\\n            }\\n            JSONArray ordered=new JSONArray();for(JSONObject row:rows.values())ordered.put(row);\\n            return new JSONObject().put(\\\"source\\\",\\\"getWindowsOnAllDisplays_selected_display_metadata\\\")\\n                    .put(\\\"display_id\\\",displayId).put(\\\"target_window_id\\\",windowId).put(\\\"target_layer\\\",targetLayer)\\n                    .put(\\\"target_native_bounds\\\",new JSONArray(region)).put(\\\"windows\\\",ordered)\\n                    .put(\\\"observed_upper_or_same_layer_overlap\\\",false).put(\\\"ime_window_observed\\\",false)\\n                    .put(\\\"other_window_roots_traversed\\\",false).put(\\\"unreported_windows_excluded\\\",false);\\n        }finally{for(AccessibilityWindowInfo window:windows)if(window!=null)window.recycle();}\\n    }\\n\",\"count\":1},{\"before\":\"        JSONArray flightNativeSnapshot;boolean flightNativeSnapshotComplete;\",\"after\":\"        JSONArray flightNativeSnapshot;boolean flightNativeSnapshotComplete;int flightNativeSnapshotText;\",\"count\":1},{\"before\":\"                            graph.flightNativeSnapshot.put(snapshotFlightNode(node,nativePath,nativeParentClass));\",\"after\":\"                            JSONObject stamp=snapshotFlightNode(node,nativePath,nativeParentClass);\\n                            int chars=stamp.getString(\\\"text\\\").length()+stamp.getString(\\\"description\\\").length();\\n                            if(graph.flightNativeSnapshotText+chars>32768)\\n                                throw new IllegalStateException(\\\"bounded full Flight snapshot text exceeded\\\");\\n                            graph.flightNativeSnapshotText+=chars;graph.flightNativeSnapshot.put(stamp);\",\"count\":1},{\"before\":\"        if(background==null||before==null||frame!=current||cancel.isCancelled()||!owns(taskId)\\n                ||before.truncated||now.truncated||before.collectionStats==null||now.collectionStats==null\",\"after\":\"        if(background==null||before==null||frame!=current||cancel.isCancelled()||!owns(taskId)\\n                ||!taskId.equals(permit.taskId)||permit.frame!=frame||permit.windowId!=before.windowId\\n                ||permit.displayId!=before.displayId||!before.sameWindow(now)\\n                ||before.truncated||now.truncated||before.collectionStats==null||now.collectionStats==null\",\"count\":1}]},{\"path\":\"src/org/trillionnium/hepta/local/LocalTaskController.java\",\"base\":{\"bytes\":113877,\"sha256\":\"7910c173995090a7d4b2fd7659a3835624088378685d9bdf5c5aaf3183831f1d\",\"git_blob_sha\":\"e0665e2326d26ca97747b89e46bc8646c49ed4e0\"},\"candidate\":{\"bytes\":116846,\"sha256\":\"68185b0bd3cf17adfb94f62b32a764ce692512ea20b438bbcdca766cff49d167\",\"git_blob_sha\":\"9c54638c63c9bdc7a885c633d2de5d702dc1175b\"},\"ordered_patches\":[{\"before\":\"    private volatile boolean running,blocked,closed;\\n\",\"after\":\"    private volatile boolean running,blocked,closed;\\n    // stop() and the final read-only result decision share one terminal boundary.\\n    private boolean terminalDecisionSealed;\\n\",\"count\":1},{\"before\":\"listener=callback;currentTaskId=id;currentActualScopeSha256=null;lastResult=null;cancelled.set(false);running=true;\",\"after\":\"listener=callback;currentTaskId=id;currentActualScopeSha256=null;lastResult=null;cancelled.set(false);terminalDecisionSealed=false;running=true;\",\"count\":1},{\"before\":\"        if(!running)return;cancelled.set(true);emit(\\\"正在停止本地任务，等待当前推理退出…\\\");\",\"after\":\"        synchronized(this){if(!running||terminalDecisionSealed)return;cancelled.set(true);}\\n        emit(\\\"正在停止本地任务，等待当前推理退出…\\\");\",\"count\":1},{\"before\":\"        String lastModelDoneStatus=null,lastModelDoneSummary=null;\",\"after\":\"        String lastModelDoneStatus=null,lastModelDoneSummary=null,acceptedCompletionModelRunId=null;\",\"count\":1},{\"before\":\"if(check.verified){finalStatus=\\\"model_reported_done\\\";summary=completion.completionSummary();modelSuccess=true;break;}\",\"after\":\"if(check.verified){finalStatus=\\\"model_reported_done\\\";summary=completion.completionSummary();modelSuccess=true;acceptedCompletionModelRunId=decisionRunId;break;}\",\"count\":1},{\"before\":\"            synchronized(handleLock){activeInference=null;}\\n            if(activeWebTask!=null){\\n                WebFlightSession.Cleanup webCleanup=\",\"after\":\"            synchronized(handleLock){activeInference=null;}\\n            WebFlightSession.Cleanup webCleanup=null;\\n            if(activeWebTask!=null){\\n                webCleanup=\",\"count\":1},{\"before\":\"            if(scope!=null)try{scope.verifyUnchanged();}catch(Exception refusal){\",\"after\":\"            boolean terminalScopeRechecked=false;\\n            if(scope!=null)try{scope.verifyUnchanged();terminalScopeRechecked=true;}catch(Exception refusal){\",\"count\":1},{\"before\":\"            boolean controllerOwnerCompletionAllowed=false;\\n            try{authorization.ready();if(controllerSuccess)controllerOwnerCompletionAllowed=authorization.frame().successAllowed();}\",\"after\":\"            boolean controllerOwnerCompletionAllowed=false;TaskAuthorization.Frame terminalOwnerFrame=null;\\n            try{authorization.ready();if(controllerSuccess)controllerOwnerCompletionAllowed=authorization.frame().successAllowed();\\n                if(TaskCompletionGate.WEB.equals(completion.contract.kind))terminalOwnerFrame=authorization.frame();}\",\"count\":1},{\"before\":\"            boolean completionVerified=(modelSuccess||controllerSuccess)&&cleanup&&modelCleanup.receiptValid&&completion.verified(completionFrame(observation));\\n            String completionActor=completionVerified?(controllerSuccess?\\\"controller/tool_workflow\\\":\\\"model_done_verified\\\"):null;\\n            java.util.Map<String,Object> completionEvidence=completion.evidence(completionFrame(observation));\\n            completionEvidence.put(\\\"observation_chain_verified\\\",completion.verified(completionFrame(observation)));\\n            completionEvidence.put(\\\"terminal_binding_and_cleanup_verified\\\",completionVerified);\",\"after\":\"            boolean completionVerified;String completionActor;java.util.Map<String,Object> completionEvidence;\\n            // All resource teardown and worker receipt checks have finished. A\\n            // cancellation that wins this lock cannot be promoted by a late CLOSE.\\n            synchronized(this){\\n                if(cleanup&&cancelled.get()){\\n                    finalStatus=\\\"cancelled\\\";modelSuccess=false;controllerSuccess=false;summary=\\\"已停止；已经发生的操作不会自动重做\\\";\\n                }\\n                NotesCompletionEvidence.Frame finalFrame=completionFrame(observation);\\n                if(TaskCompletionGate.WEB.equals(completion.contract.kind)){\\n                    boolean helperReleased=webCleanup!=null&&webCleanup.known&&activeWebTask!=null\\n                            &&taskId.equals(activeWebTask.taskId)&&activeWebTask.released();\\n                    boolean backgroundReleased=background!=null&&backgroundCleanup!=null&&backgroundCleanup.known\\n                            &&background.released()&&taskId.equals(background.taskId)\\n                            &&authorization.authorization.instructionSha256.equals(background.ownerSha256)\\n                            &&finalFrame!=null&&background.generation.equals(finalFrame.backgroundGeneration)\\n                            &&background.displayId()==finalFrame.displayId;\\n                    TaskCompletionGate.Check terminal=completion.terminalWebCheck(activeWebTask,finalFrame,terminalOwnerFrame,\\n                            steps,acceptedCompletionModelRunId,modelSuccess&&\\\"model_reported_done\\\".equals(finalStatus),\\n                            cleanup,helperReleased,backgroundReleased,terminalScopeRechecked,cancelled.get(),\\n                            modelCleanup.processStarted,modelCleanup.processExitObserved,modelCleanup.exitCode,modelCleanup.receiptValid,\\n                            modelCleanup.taskId,modelCleanup.generation,modelCleanup.receiptSha256);\\n                    completionVerified=terminal.verified;\\n                    completionEvidence=new java.util.LinkedHashMap<String,Object>(terminal.evidence);\\n                    if(modelSuccess&&!completionVerified){\\n                        modelSuccess=false;finalStatus=\\\"partial\\\";summary=\\\"网页结果曾被观察，但终态身份或清理证明未通过，未确认任务完成。\\\";\\n                    }\\n                }else{\\n                    completionVerified=(modelSuccess||controllerSuccess)&&cleanup&&modelCleanup.receiptValid&&completion.verified(finalFrame);\\n                    completionEvidence=completion.evidence(finalFrame);\\n                    completionEvidence.put(\\\"observation_chain_verified\\\",completion.verified(finalFrame));\\n                }\\n                completionActor=completionVerified?(controllerSuccess?\\\"controller/tool_workflow\\\":\\\"model_done_verified\\\"):null;\\n                completionEvidence.put(\\\"terminal_binding_and_cleanup_verified\\\",completionVerified);\\n                terminalDecisionSealed=true;\\n            }\",\"count\":1}]},{\"path\":\"src/org/trillionnium/hepta/local/TaskCompletionGate.java\",\"base\":{\"bytes\":32946,\"sha256\":\"cce85ab866bbb2d5bb287594152513b8ee178dae9107a3b490975f0a229857d8\",\"git_blob_sha\":\"d8a894c9bd3ece4a7dca922cb5fda8a84447c789\"},\"candidate\":{\"bytes\":49971,\"sha256\":\"ad417d98fbd7b12bf4373270a1206c11984682c9f35b7b4a5179bb9fbff7ba98\",\"git_blob_sha\":\"48323262aaf10962f0a481cafc18c56bc82e936b\"},\"ordered_patches\":[{\"before\":\"    private WebTaskDomain webDomain;\\n\",\"after\":\"    private WebTaskDomain webDomain;\\n    // Completion is a historical, read-only result, not a retained action domain.\\n    // Only successClaim may create a candidate. The real Session consumes it once\\n    // before retirement, and only its authenticated ordinary CLOSE may seal it.\\n    private WebTaskDomain claimedWebDomain;\\n    private WebCompletionSnapshot webCompletionCandidate;\\n    private WebCloseAttempt pendingWebClose;\\n    private ClosedWebCompletion closedWebCompletion;\\n    private boolean webCloseStarted,webTerminalConsumed;\\n    private long webClearSequence;\\n\\n    private static final class WebCompletionSnapshot {\\n        final String task,owner,contract,authorization,observation,frameSha,binding,instance,generation,run;\\n        final int step,display,window;final long epoch;\\n        final Map<String,Object> page,result;\\n        WebCompletionSnapshot(TaskCompletionGate gate,WebTaskDomain domain,NotesCompletionEvidence.Frame frame,int step,String run){\\n            task=gate.taskId;owner=gate.contract.ownerSha256;contract=gate.contract.contractSha256;\\n            authorization=gate.authorization.sha256;observation=frame.observationId;frameSha=webFrameSha(frame);\\n            require(frameSha!=null&&frame.displayId>0&&frame.backgroundGeneration!=null,\\\"complete final native observation required\\\");\\n            page=immutableMap(domain.evidence());result=immutableMap(domain.resultRecord());\\n            binding=requiredText(page,\\\"binding_sha256\\\");instance=requiredText(page,\\\"webview_instance\\\");\\n            generation=frame.backgroundGeneration;display=frame.displayId;window=frame.windowId;\\n            epoch=requiredInteger(page,\\\"navigation_epoch\\\");this.step=step;this.run=run;\\n            require(hex64(binding)&&hex64(requiredText(page,\\\"contract_sha256\\\"))&&epoch>=0\\n                    &&task.equals(page.get(\\\"task_id\\\"))&&owner.equals(page.get(\\\"owner_sha256\\\"))\\n                    &&authorization.equals(page.get(\\\"authorization_sha256\\\"))\\n                    &&observation.equals(page.get(\\\"observation_id\\\"))&&generation.equals(page.get(\\\"background_generation\\\"))\\n                    &&requiredInteger(page,\\\"display_id\\\")==display&&requiredInteger(page,\\\"window_id\\\")==window,\\n                    \\\"verified provider identity differs from its native final observation\\\");\\n            require(task.equals(result.get(\\\"task_id\\\"))&&owner.equals(result.get(\\\"owner_sha256\\\"))\\n                    &&page.get(\\\"contract_sha256\\\").equals(result.get(\\\"contract_sha256\\\"))\\n                    &&binding.equals(result.get(\\\"binding_sha256\\\"))&&instance.equals(result.get(\\\"webview_instance\\\"))\\n                    &&epoch==requiredInteger(result,\\\"navigation_epoch\\\")\\n                    &&observation.equals(result.get(\\\"observation_id\\\"))\\n                    &&Objects.equals(page.get(\\\"observation_state_sha256\\\"),result.get(\\\"observation_state_sha256\\\"))\\n                    &&requiredInteger(result,\\\"display_id\\\")==display&&requiredInteger(result,\\\"window_id\\\")==window\\n                    &&Boolean.FALSE.equals(result.get(\\\"business_verified\\\")),\\n                    \\\"actual read-only result differs from its verified provider record\\\");\\n        }\\n    }\\n    static final class WebCloseAttempt {\\n        private final TaskCompletionGate gate;private final Object lease;\\n        private final WebCompletionSnapshot snapshot;private final long expectedClearSequence;\\n        private boolean consumed;\\n        private WebCloseAttempt(TaskCompletionGate gate,Object lease,WebCompletionSnapshot snapshot,long expectedClearSequence){\\n            this.gate=gate;this.lease=lease;this.snapshot=snapshot;this.expectedClearSequence=expectedClearSequence;\\n        }\\n    }\\n    private static final class ClosedWebCompletion {\\n        final Object lease;final WebCompletionSnapshot snapshot;final String callbackSha;\\n        ClosedWebCompletion(Object lease,WebCompletionSnapshot snapshot,String callbackSha){\\n            this.lease=lease;this.snapshot=snapshot;this.callbackSha=callbackSha;\\n        }\\n    }\\n    /** Called once by the live Session immediately before its existing clear.\\n     * A missing, changed, errored or cancelled claim retires without a candidate. */\\n    synchronized WebCloseAttempt beginWebClose(Object lease,WebTaskDomain current,String actualTask,String binding,String reason){\\n        if(webCloseStarted){abortWebClose(pendingWebClose);return null;}\\n        webCloseStarted=true;closedWebCompletion=null;\\n        WebCompletionSnapshot candidate=webCompletionCandidate;WebTaskDomain claimed=claimedWebDomain;\\n        webCompletionCandidate=null;claimedWebDomain=null;\\n        if(!WEB.equals(contract.kind)||lease==null||!\\\"normal\\\".equals(reason)||identityInvalid\\n                ||webTerminalConsumed||candidate==null||current==null||current!=webDomain||current!=claimed\\n                ||!taskId.equals(actualTask)||!candidate.binding.equals(binding))return null;\\n        try{\\n            if(!candidate.page.equals(immutableMap(current.evidence()))\\n                    ||!candidate.result.equals(immutableMap(current.resultRecord())))return null;\\n        }catch(RuntimeException invalid){return null;}\\n        pendingWebClose=new WebCloseAttempt(this,lease,candidate,webClearSequence+1);\\n        return pendingWebClose;\\n    }\\n    /** The caller has already verified the actual typed CLOSE and persisted\\n     * journal.closeKnown. A recovery/unstarted/unknown close is never this proof. */\\n    synchronized boolean webCloseKnown(WebCloseAttempt attempt,Object lease,String actualTask,String binding,\\n            String status,String instance,long epoch,int display,int window,String callbackSha){\\n        boolean good=attempt!=null&&attempt==pendingWebClose&&attempt.gate==this&&!attempt.consumed\\n                &&attempt.lease==lease&&webCloseStarted&&!webTerminalConsumed&&webDomain==null\\n                &&webClearSequence==attempt.expectedClearSequence&&!identityInvalid\\n                &&taskId.equals(actualTask)&&attempt.snapshot.binding.equals(binding)\\n                &&\\\"closed\\\".equals(status)&&attempt.snapshot.instance.equals(instance)\\n                &&attempt.snapshot.epoch==epoch&&attempt.snapshot.display==display&&attempt.snapshot.window==window\\n                &&hex64(callbackSha);\\n        if(attempt!=null)attempt.consumed=true;\\n        pendingWebClose=null;closedWebCompletion=null;\\n        if(!good)return false;\\n        closedWebCompletion=new ClosedWebCompletion(lease,attempt.snapshot,callbackSha);return true;\\n    }\\n    /** Unknown or failed closes consume the candidate permanently, including\\n     * callbacks that arrive after cancellation or a later reconciliation. */\\n    synchronized void abortWebClose(WebCloseAttempt attempt){\\n        if(attempt!=null)attempt.consumed=true;\\n        if(pendingWebClose!=null)pendingWebClose.consumed=true;\\n        pendingWebClose=null;closedWebCompletion=null;claimedWebDomain=null;webCompletionCandidate=null;\\n    }\\n    /** The only post-retirement completion path. Inputs come from the actual\\n     * controller cleanup objects; model/JSON claims cannot construct the private\\n     * closed proof. This consumes the terminal attempt even when a check fails. */\\n    synchronized Check terminalWebCheck(Object lease,NotesCompletionEvidence.Frame current,TaskAuthorization.Frame owner,\\n            int step,String modelRun,boolean modelSuccess,boolean allCleanupKnown,boolean helperReleased,\\n            boolean backgroundReleased,boolean scopeRechecked,boolean cancelled,\\n            boolean processStarted,boolean processExitObserved,Integer exitCode,boolean receiptValid,\\n            String workerTask,String workerGeneration,String workerReceiptSha){\\n        ClosedWebCompletion closed=closedWebCompletion;closedWebCompletion=null;\\n        boolean first=!webTerminalConsumed;webTerminalConsumed=true;\\n        boolean snapshot=first&&WEB.equals(contract.kind)&&closed!=null&&closed.lease==lease\\n                &&pendingWebClose==null&&webCloseStarted&&webDomain==null&&!identityInvalid&&sameDomain(current)\\n                &&closed.snapshot.task.equals(taskId)&&closed.snapshot.owner.equals(contract.ownerSha256)\\n                &&closed.snapshot.contract.equals(contract.contractSha256)&&closed.snapshot.authorization.equals(authorization.sha256)\\n                &&Objects.equals(closed.snapshot.frameSha,webFrameSha(current))\\n                &&step==closed.snapshot.step&&Objects.equals(modelRun,closed.snapshot.run);\\n        boolean ownerBound=owner!=null&&owner.authorization==authorization&&taskId.equals(owner.taskId)&&owner.successAllowed();\\n        boolean nativeBound=processStarted&&processExitObserved&&Integer.valueOf(0).equals(exitCode)&&receiptValid\\n                &&taskId.equals(workerTask)&&id(workerGeneration)&&hex64(workerReceiptSha);\\n        boolean verified=snapshot&&modelSuccess&&allCleanupKnown&&helperReleased&&backgroundReleased\\n                &&scopeRechecked&&ownerBound&&!cancelled&&nativeBound;\\n        Map<String,Object> value=evidence(current),terminal=new LinkedHashMap<String,Object>();\\n        terminal.put(\\\"schema\\\",\\\"hepta.web-terminal-completion.v1\\\");terminal.put(\\\"task_id\\\",taskId);\\n        terminal.put(\\\"owner_sha256\\\",contract.ownerSha256);terminal.put(\\\"contract_sha256\\\",contract.contractSha256);\\n        terminal.put(\\\"authorization_sha256\\\",authorization.sha256);terminal.put(\\\"one_terminal_attempt\\\",first);\\n        terminal.put(\\\"closed_result_snapshot_verified\\\",snapshot);terminal.put(\\\"live_action_domain_retired\\\",webDomain==null&&webCloseStarted);\\n        terminal.put(\\\"model_success_claim_verified_before_close\\\",snapshot);terminal.put(\\\"all_cleanup_known\\\",allCleanupKnown);\\n        terminal.put(\\\"helper_released\\\",helperReleased);terminal.put(\\\"background_released\\\",backgroundReleased);\\n        terminal.put(\\\"scope_rechecked_after_worker_exit\\\",scopeRechecked);terminal.put(\\\"owner_rechecked_after_worker_exit\\\",ownerBound);\\n        terminal.put(\\\"cancelled\\\",cancelled);terminal.put(\\\"native_parent_session_bound\\\",nativeBound);\\n        terminal.put(\\\"worker_task_id\\\",workerTask);terminal.put(\\\"worker_generation\\\",workerGeneration);\\n        terminal.put(\\\"worker_receipt_sha256\\\",workerReceiptSha);terminal.put(\\\"terminal_verified\\\",verified);\\n        terminal.put(\\\"grants_tool_authority\\\",false);terminal.put(\\\"business_verified\\\",false);\\n        if(snapshot){\\n            WebCompletionSnapshot result=closed.snapshot;\\n            terminal.put(\\\"binding_sha256\\\",result.binding);terminal.put(\\\"webview_instance\\\",result.instance);\\n            terminal.put(\\\"navigation_epoch\\\",result.epoch);terminal.put(\\\"display_id\\\",result.display);terminal.put(\\\"window_id\\\",result.window);\\n            terminal.put(\\\"background_generation\\\",result.generation);terminal.put(\\\"final_observation_id\\\",result.observation);\\n            terminal.put(\\\"final_observation_sha256\\\",result.frameSha);terminal.put(\\\"accepted_model_run_id\\\",result.run);\\n            terminal.put(\\\"accepted_model_step\\\",result.step);terminal.put(\\\"actual_close_callback_canonical_sha256\\\",closed.callbackSha);\\n            value.put(\\\"official_page\\\",result.page);\\n            Map<String,Object> publicResult=new LinkedHashMap<String,Object>(result.result);\\n            publicResult.put(\\\"completion_gate_accepted\\\",verified);publicResult.put(\\\"action_domain_retired\\\",true);\\n            value.put(\\\"public_web_result\\\",immutableMap(publicResult));\\n        }\\n        value.put(\\\"completion_verified\\\",verified);value.put(\\\"live_observation_verified\\\",false);\\n        value.put(\\\"observation_chain_verified\\\",snapshot);value.put(\\\"terminal_binding_and_cleanup_verified\\\",verified);\\n        value.put(\\\"terminal_web_completion\\\",immutableMap(terminal));\\n        List<String> absent=new ArrayList<String>(missing(current));\\n        if(!verified)absent.add(\\\"closed_web_terminal_binding_or_cleanup_missing\\\");\\n        value.put(\\\"missing\\\",verified?Collections.<String>emptyList():Collections.unmodifiableList(absent));\\n        return new Check(verified,false,immutableMap(value));\\n    }\\n    private static String requiredText(Map<String,Object> value,String key){\\n        Object item=value.get(key);require(item instanceof String&&!((String)item).isEmpty(),\\\"required provider text \\\"+key);return (String)item;\\n    }\\n    private static long requiredInteger(Map<String,Object> value,String key){\\n        Object item=value.get(key);require(item instanceof Integer||item instanceof Long,\\\"required provider integer \\\"+key);return ((Number)item).longValue();\\n    }\\n    private static boolean hex64(String value){return value!=null&&value.matches(\\\"[0-9a-f]{64}\\\");}\\n    private static Map<String,Object> immutableMap(Map<String,Object> value){\\n        @SuppressWarnings(\\\"unchecked\\\") Map<String,Object> copy=(Map<String,Object>)immutableValue(value,0,new int[]{50000});\\n        return copy;\\n    }\\n    private static Object immutableValue(Object value,int depth,int[] budget){\\n        require(depth<=64&&--budget[0]>=0,\\\"bounded immutable result evidence required\\\");\\n        if(value==null||value instanceof String||value instanceof Boolean\\n                ||value instanceof Byte||value instanceof Short||value instanceof Integer||value instanceof Long\\n                ||value instanceof java.math.BigInteger||value instanceof java.math.BigDecimal)return value;\\n        if(value instanceof Double){require(!Double.isNaN((Double)value)&&!Double.isInfinite((Double)value),\\\"finite result number\\\");return value;}\\n        if(value instanceof Float){require(!Float.isNaN((Float)value)&&!Float.isInfinite((Float)value),\\\"finite result number\\\");return value;}\\n        if(value instanceof Map){\\n            Map<String,Object> copy=new LinkedHashMap<String,Object>();\\n            for(Map.Entry<?,?> entry:((Map<?,?>)value).entrySet()){\\n                require(entry.getKey() instanceof String,\\\"result evidence keys must be text\\\");\\n                copy.put((String)entry.getKey(),immutableValue(entry.getValue(),depth+1,budget));\\n            }return Collections.unmodifiableMap(copy);\\n        }\\n        if(value instanceof List){\\n            List<Object> copy=new ArrayList<Object>();\\n            for(Object item:(List<?>)value)copy.add(immutableValue(item,depth+1,budget));\\n            return Collections.unmodifiableList(copy);\\n        }\\n        throw new IllegalArgumentException(\\\"completion: unsupported mutable result evidence type\\\");\\n    }\\n    private static String webFrameSha(NotesCompletionEvidence.Frame frame){\\n        if(!domainShape(frame)||!id(frame.observationId)||frame.packageName==null||frame.nodesTruncated||frame.nodes==null)return null;\\n        StringBuilder value=new StringBuilder(\\\"hepta.web-final-native-frame.v1\\\");\\n        webField(value,frame.observationId);webField(value,frame.packageName);webField(value,frame.windowId);\\n        webField(value,frame.displayId);webField(value,frame.backgroundGeneration);webField(value,frame.windowType);\\n        webField(value,frame.metadataObserved);webField(value,frame.nodesTruncated);webField(value,frame.nodes.size());\\n        for(NotesCompletionEvidence.Node node:frame.nodes){\\n            if(node==null||node.childText==null)return null;\\n            webField(value,node.id);webField(value,node.packageName);webField(value,node.text);webField(value,node.label);\\n            webField(value,node.viewId);webField(value,node.inputTextSha256);webField(value,node.left);webField(value,node.top);\\n            webField(value,node.right);webField(value,node.bottom);webField(value,node.editable);webField(value,node.clickable);\\n            webField(value,node.scrollable);webField(value,node.enabled);webField(value,node.password);\\n            webField(value,node.observedAppTreeSignature);webField(value,node.childText.fingerprint);webField(value,node.childText.visited);\\n        }\\n        return hash(value.toString());\\n    }\\n    private static void webField(StringBuilder out,Object value){\\n        if(value==null){out.append(\\\"|-1:\\\");return;}String text=String.valueOf(value);out.append('|').append(text.length()).append(':').append(text);\\n    }\\n\",\"count\":1},{\"before\":\"    void bindWebDomain(WebTaskDomain value){\\n\",\"after\":\"    synchronized void bindWebDomain(WebTaskDomain value){\\n        if(webCloseStarted){abortWebClose(pendingWebClose);throw new IllegalArgumentException(\\\"completion: web action domain is retired\\\");}\\n        webCompletionCandidate=null;claimedWebDomain=null;\\n\",\"count\":1},{\"before\":\"    void clearWebDomain(){webDomain=null;}\\n\",\"after\":\"    synchronized void clearWebDomain(){\\n        webDomain=null;claimedWebDomain=null;webCompletionCandidate=null;webClearSequence++;\\n        if(pendingWebClose==null)closedWebCompletion=null;\\n    }\\n\",\"count\":1},{\"before\":\"        require(webDomain!=null&&frame!=null&&webDomain.observationId.equals(frame.observationId)\\n\",\"after\":\"        require(!webCloseStarted&&webDomain!=null&&frame!=null&&webDomain.observationId.equals(frame.observationId)\\n\",\"count\":1},{\"before\":\"    public void invalidateInstalled(String reason){\",\"after\":\"    public synchronized void invalidateInstalled(String reason){\",\"count\":1},{\"before\":\"    public void observed(NotesCompletionEvidence.Frame frame){\\n\",\"after\":\"    public synchronized void observed(NotesCompletionEvidence.Frame frame){\\n        if(WEB.equals(contract.kind)){\\n            if(webCloseStarted)abortWebClose(pendingWebClose);\\n            else if(webCompletionCandidate!=null&&!Objects.equals(webCompletionCandidate.frameSha,webFrameSha(frame))){\\n                webCompletionCandidate=null;claimedWebDomain=null;\\n            }\\n        }\\n\",\"count\":1},{\"before\":\"    public void action(int step,String run,ActionDecision action,boolean accepted,boolean dispatched,boolean stale,\\n\",\"after\":\"    public synchronized void action(int step,String run,ActionDecision action,boolean accepted,boolean dispatched,boolean stale,\\n\",\"count\":1},{\"before\":\"        observed(before);\\n        if(!domainShape(before)||!domainShape(after))\",\"after\":\"        if(WEB.equals(contract.kind)){webCompletionCandidate=null;claimedWebDomain=null;}\\n        observed(before);\\n        if(!domainShape(before)||!domainShape(after))\",\"count\":1},{\"before\":\"    public Check successClaim(int step,String run,NotesCompletionEvidence.Frame current,boolean finalObservationStable){\\n\",\"after\":\"    public synchronized Check successClaim(int step,String run,NotesCompletionEvidence.Frame current,boolean finalObservationStable){\\n\",\"count\":1},{\"before\":\"        claim.put(\\\"completion_verified\\\",verified);claims.add(claim);\\n\",\"after\":\"        claim.put(\\\"completion_verified\\\",verified);claims.add(claim);\\n        if(WEB.equals(contract.kind)){\\n            webCompletionCandidate=null;claimedWebDomain=null;\\n            if(verified&&!webCloseStarted){\\n                webCompletionCandidate=new WebCompletionSnapshot(this,webDomain,current,step,run);claimedWebDomain=webDomain;\\n            }\\n        }\\n\",\"count\":1},{\"before\":\"    public boolean verified(NotesCompletionEvidence.Frame current){\\n        if(WEB.equals(contract.kind))return domainBound\",\"after\":\"    public synchronized boolean verified(NotesCompletionEvidence.Frame current){\\n        if(WEB.equals(contract.kind))return !webCloseStarted&&domainBound\",\"count\":1}]},{\"path\":\"src/org/trillionnium/hepta/local/WebFlightNativeStability.java\",\"base\":null,\"candidate\":{\"bytes\":23349,\"sha256\":\"503078f251696fb542912e5270efca13439ebcece4db8b3473e7fcb543b4fc2d\",\"git_blob_sha\":\"5d41e41c7e6c447f4dba598a12f21673c168603b\"},\"raw_utf8\":\"package org.trillionnium.hepta.local;\\n\\nimport org.json.JSONArray;\\nimport org.json.JSONObject;\\nimport org.trillionnium.hepta.webprotocol.WebDomCanonical;\\nimport org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;\\nimport java.util.ArrayList;\\nimport java.util.Collections;\\nimport java.util.HashSet;\\nimport java.util.List;\\nimport java.util.Map;\\nimport java.util.Set;\\nimport java.util.TreeMap;\\nimport java.util.TreeSet;\\n\\n/**\\n * A compiled, homepage-only booking predicate. It is neither a general\\n * stable-tree waiver nor an action executor. The service keeps the original\\n * NodeRef and all ordinary authority, freshness and platform-action checks.\\n */\\nfinal class WebFlightNativeStability {\\n    static final String PURPOSE=\\\"open_public_booking_form\\\";\\n    static final String LABEL=\\\"机票预订按钮，点按两次即可激活\\\";\\n    static final int MAX_NATIVE_NODES=512;\\n    private WebFlightNativeStability(){}\\n\\n    static final class Permit {\\n        final PhoneObservation frame;\\n        final String taskId,targetId,targetPath,run,actionKey,bindingSha,instance;\\n        final int displayId,windowId;\\n        final long epoch;\\n        private final int[] targetBounds;\\n        private final String domProof;\\n        private Permit(WebTaskDomain domain,PhoneObservation frame,PhoneObservation.Node target,\\n                       String run,ActionDecision action,WebEvidenceReceipt receipt,JSONObject proof)throws Exception{\\n            this.frame=frame;taskId=domain.taskId;targetId=target.id;targetPath=target.nativeTreePath;\\n            this.run=run;actionKey=key(action);bindingSha=receipt.bindingSha;instance=receipt.instance;\\n            displayId=receipt.displayId;windowId=receipt.windowId;epoch=receipt.epoch;\\n            targetBounds=new int[]{target.bounds.left,target.bounds.top,target.bounds.right,target.bounds.bottom};\\n            domProof=WebDomCanonical.canonical(proof);\\n        }\\n        int[] bounds(){return targetBounds.clone();}\\n        JSONObject domEvidence()throws Exception{return new JSONObject(domProof);}\\n        boolean matches(PhoneObservation current,ActionDecision action,String actualRun){\\n            return frame==current&&run.equals(actualRun)&&actionKey.equals(key(action))\\n                    &&targetId.equals(action.nodeId)&&frame.id.equals(action.observationId);\\n        }\\n    }\\n\\n    static Permit prepare(WebTaskDomain domain,PhoneObservation frame,ActionDecision action,String run,\\n                          WebEvidenceReceipt observed,WebEvidenceReceipt fresh)throws Exception{\\n        if(domain==null||domain.flight==null||!\\\"click\\\".equals(action.action)\\n                ||!\\\"official_home\\\".equals(domain.phase)||!PURPOSE.equals(domain.flight.purpose(action.nodeId)))return null;\\n        need(\\\"https://m.csair.com/\\\".equals(domain.url)&&frame!=null&&observed!=null&&fresh!=null,\\n                \\\"booking exception requires the actual official homepage captures\\\");\\n        need(!frame.nodesTruncated&&frame.collectionStats!=null&&!frame.collectionStats.truncated()\\n                &&frame.collectionStats.pending==0&&frame.collectionStats.childSlotsOmitted==0,\\n                \\\"complete original native observation required\\\");\\n        PhoneObservation.Node target=null;\\n        for(PhoneObservation.Node node:frame.nodes)if(node.id.equals(action.nodeId)){\\n            need(target==null,\\\"duplicate original native target\\\");target=node;\\n        }\\n        need(target!=null&&target.nativeTreePath!=null&&target.nativeParentClass!=null\\n                &&\\\"android.widget.Button\\\".equals(target.className)&&LABEL.equals(target.label())\\n                &&WebEvidenceProtocol.HELPER_PACKAGE.equals(target.packageName)&&target.viewId.isEmpty()\\n                &&target.clickable&&target.enabled&&!target.password&&!target.editable&&!target.scrollable,\\n                \\\"original native booking button required\\\");\\n        need(\\\"captured\\\".equals(observed.status)&&\\\"captured\\\".equals(fresh.status)\\n                &&observed.stability().rawEqual&&fresh.stability().rawEqual\\n                &&observed.bindingSha.equals(fresh.bindingSha)&&observed.instance.equals(fresh.instance)\\n                &&observed.epoch==fresh.epoch&&observed.windowId==fresh.windowId\\n                &&observed.displayId==fresh.displayId&&observed.url.equals(fresh.url)\\n                &&domain.instance.equals(fresh.instance)&&domain.epoch==fresh.epoch\\n                &&frame.windowId==fresh.windowId&&domain.displayId==fresh.displayId,\\n                \\\"same verified full-raw capture lease required\\\");\\n        WebNativeGeometry before=WebNativeGeometry.read(observed.capture(),observed.dom(),observed.displayId,\\n                observed.windowId,observed.stability());\\n        WebNativeGeometry after=WebNativeGeometry.read(fresh.capture(),fresh.dom(),fresh.displayId,\\n                fresh.windowId,fresh.stability());\\n        need(before!=null&&after!=null&&before.same(after),\\\"native capture geometry changed\\\");\\n        JSONObject proof=compareDom(observed.dom(),fresh.dom())\\n                .put(\\\"first_dom_sha256\\\",observed.domSha).put(\\\"fresh_dom_sha256\\\",fresh.domSha)\\n                .put(\\\"first_capture_request_nonce\\\",observed.callback().get(\\\"request_nonce\\\"))\\n                .put(\\\"fresh_capture_request_nonce\\\",fresh.callback().get(\\\"request_nonce\\\"))\\n                .put(\\\"native_geometry_sha256\\\",after.fingerprint);\\n        return new Permit(domain,frame,target,run,action,fresh,proof);\\n    }\\n\\n    /** Complete DOM comparison; only this observed eight-image slider may move. */\\n    static JSONObject compareDom(JSONObject before,JSONObject after)throws Exception{\\n        Map<String,JSONObject> a=domNodes(before),b=domNodes(after);\\n        need(a.keySet().equals(b.keySet()),\\\"homepage DOM membership changed\\\");\\n        need(WebDomCanonical.same(without(before,\\\"nodes\\\"),without(after,\\\"nodes\\\")),\\n                \\\"homepage DOM metadata changed\\\");\\n        String slider=unique(a,\\\"id\\\",\\\"slider4\\\"),booking=unique(a,\\\"id\\\",\\\"booking\\\");\\n        need(\\\"ul\\\".equals(a.get(slider).get(\\\"tag\\\"))&&\\\"div\\\".equals(a.get(booking).get(\\\"tag\\\"))\\n                &&!inside(booking,slider)&&a.get(booking).getBoolean(\\\"visible_in_viewport\\\"),\\n                \\\"known slider and separate visible booking region required\\\");\\n        Set<String> allowed=new HashSet<String>();allowed.add(slider);\\n        Set<String> ids=new HashSet<String>();\\n        for(Map.Entry<String,JSONObject> e:a.entrySet()){\\n            JSONObject n=e.getValue();String path=e.getKey();\\n            if(slider.equals(n.opt(\\\"parent_path\\\"))){\\n                need(\\\"li\\\".equals(n.get(\\\"tag\\\"))&&n.getString(\\\"id\\\").matches(\\\"advertising[0-7]\\\")\\n                        &&ids.add(n.getString(\\\"id\\\")),\\\"unexpected slider child\\\");\\n                allowed.add(path);int images=0;\\n                for(Map.Entry<String,JSONObject> child:a.entrySet())if(path.equals(child.getValue().opt(\\\"parent_path\\\"))){\\n                    need(\\\"img\\\".equals(child.getValue().get(\\\"tag\\\"))&&child.getValue().getString(\\\"id\\\").isEmpty(),\\n                            \\\"slider child is not an observed plain image\\\");\\n                    allowed.add(child.getKey());images++;\\n                }\\n                need(images==1,\\\"slider image membership changed\\\");\\n            }\\n        }\\n        need(ids.size()==8&&allowed.size()==17,\\\"exact eight-image carousel required\\\");\\n        double delta=rect(b.get(slider),\\\"rect_css_pixels\\\")[0]-rect(a.get(slider),\\\"rect_css_pixels\\\")[0];\\n        double[] root=rect(a.get(slider),\\\"rect_css_pixels\\\");\\n        need(Math.abs(delta)<=root[2]-root[0],\\\"carousel translation exceeds its observed width\\\");\\n        JSONArray changes=new JSONArray();\\n        boolean button=false;\\n        for(String path:a.keySet()){\\n            JSONObject x=a.get(path),y=b.get(path);String tag=x.getString(\\\"tag\\\");\\n            if(x.getBoolean(\\\"visible_in_viewport\\\")&&(\\\"iframe\\\".equals(tag)||\\\"canvas\\\".equals(tag)\\n                    ||\\\"video\\\".equals(tag)||\\\"dialog\\\".equals(tag)||\\\"dialog\\\".equals(x.optString(\\\"role\\\"))\\n                    ||\\\"true\\\".equals(x.optString(\\\"aria_modal\\\"))))throw new IllegalArgumentException(\\\"observed overlay or embedded surface\\\");\\n            if(inside(path,booking)&&\\\"button\\\".equals(x.optString(\\\"role\\\"))\\n                    &&LABEL.equals(x.optString(\\\"aria_label\\\"))&&\\\"机票预订\\\".equals(x.optString(\\\"text\\\"))\\n                    &&x.getBoolean(\\\"visible_in_viewport\\\")){need(!button,\\\"ambiguous booking label\\\");button=true;}\\n            if(inside(path,slider))need(allowed.contains(path),\\\"unrecognized carousel descendant\\\");\\n            if(!allowed.contains(path)){\\n                need(WebDomCanonical.same(x,y),\\\"non-carousel DOM changed: \\\"+path);continue;\\n            }\\n            need(x.getString(\\\"text\\\").trim().isEmpty()&&x.optString(\\\"role\\\").isEmpty()\\n                    &&x.optString(\\\"aria_label\\\").isEmpty()&&x.isNull(\\\"href_raw\\\")&&x.isNull(\\\"href_resolved\\\")\\n                    &&x.isNull(\\\"link_target\\\")&&!x.getBoolean(\\\"hidden_attr\\\")&&!x.getBoolean(\\\"inert_attr\\\"),\\n                    \\\"carousel node carries unapproved semantics\\\");\\n            need(WebDomCanonical.same(without(x,\\\"rect_css_pixels\\\",\\\"visible_in_viewport\\\"),\\n                    without(y,\\\"rect_css_pixels\\\",\\\"visible_in_viewport\\\")),\\\"carousel semantics changed\\\");\\n            double[] r=rect(x,\\\"rect_css_pixels\\\"),s=rect(y,\\\"rect_css_pixels\\\");\\n            need(s[1]==r[1]&&s[3]==r[3]&&s[2]-s[0]==r[2]-r[0]\\n                    &&s[0]-r[0]==delta&&s[2]-r[2]==delta,\\\"carousel is not one horizontal translation\\\");\\n            if(!WebDomCanonical.same(x,y))changes.put(new JSONObject().put(\\\"path\\\",path).put(\\\"before\\\",x).put(\\\"after\\\",y));\\n        }\\n        need(button,\\\"complete unchanged booking button missing\\\");\\n        return new JSONObject().put(\\\"schema\\\",\\\"hepta.csair-home-dom-scope.v1\\\")\\n                .put(\\\"scope\\\",\\\"official_home_booking_with_observed_slider4_horizontal_translation\\\")\\n                .put(\\\"slider_dom_path\\\",slider).put(\\\"booking_dom_path\\\",booking)\\n                .put(\\\"horizontal_translation_css_pixels\\\",delta).put(\\\"changes\\\",changes)\\n                .put(\\\"whole_dom_equal\\\",WebDomCanonical.same(before,after))\\n                .put(\\\"all_other_dom_records_equal\\\",true).put(\\\"coordinates_used_for_input\\\",false)\\n                .put(\\\"fully_unoccluded_claimed\\\",false).put(\\\"business_verified\\\",false);\\n    }\\n\\n    /**\\n     * Both arrays are complete snapshots of the service's actual native traversal,\\n     * including ancestors and nonretained nodes. Native path pairs observations;\\n     * the model's original NodeRef is separately checked by the service.\\n     */\\n    static JSONObject compareNative(JSONArray before,JSONArray after,String targetPath)throws Exception{\\n        Map<String,JSONObject> a=nativeNodes(before),b=nativeNodes(after);\\n        need(a.keySet().equals(b.keySet()),\\\"native traversal membership changed\\\");\\n        JSONObject target=a.get(targetPath);\\n        need(target!=null&&\\\"android.widget.Button\\\".equals(target.get(\\\"class\\\"))\\n                &&LABEL.equals(target.get(\\\"text\\\"))&&target.getString(\\\"description\\\").isEmpty()\\n                &&target.getBoolean(\\\"visible\\\")&&target.getBoolean(\\\"enabled\\\")\\n                &&target.getBoolean(\\\"clickable\\\")&&!target.getBoolean(\\\"editable\\\")\\n                &&!target.getBoolean(\\\"scrollable\\\")&&!target.getBoolean(\\\"password\\\"),\\n                \\\"same actual native booking target required\\\");\\n        String slider=unique(a,\\\"view_id\\\",\\\"slider4\\\"),booking=unique(a,\\\"view_id\\\",\\\"booking\\\");\\n        JSONObject container=a.get(slider);\\n        need(\\\"android.widget.ListView\\\".equals(container.get(\\\"class\\\"))&&container.getBoolean(\\\"visible\\\")\\n                &&container.getInt(\\\"children\\\")==8&&inside(targetPath,booking)\\n                &&!inside(targetPath,slider)&&!inside(booking,slider),\\\"separate original native booking and slider required\\\");\\n        need(ancestorClass(a,targetPath,\\\"android.webkit.WebView\\\")!=null\\n                &&ancestorClass(a,targetPath,\\\"android.webkit.WebView\\\").equals(ancestorClass(a,slider,\\\"android.webkit.WebView\\\")),\\n                \\\"booking and carousel must retain the same actual WebView ancestor\\\");\\n        Set<String> changedScope=new HashSet<String>(),ids=new HashSet<String>();\\n        for(Map.Entry<String,JSONObject> e:a.entrySet())if(parent(e.getKey()).equals(slider)){\\n            JSONObject n=e.getValue();\\n            need(\\\"android.view.View\\\".equals(n.get(\\\"class\\\"))&&n.getString(\\\"view_id\\\").matches(\\\"advertising[0-7]\\\")\\n                    &&ids.add(n.getString(\\\"view_id\\\"))&&n.getInt(\\\"children\\\")==1,\\\"unexpected native carousel child\\\");\\n            String image=e.getKey()+\\\"/0\\\";JSONObject child=a.get(image);\\n            need(child!=null&&\\\"android.widget.Image\\\".equals(child.get(\\\"class\\\"))&&child.getInt(\\\"children\\\")==0,\\n                    \\\"native carousel image missing\\\");\\n            changedScope.add(e.getKey());changedScope.add(image);\\n        }\\n        need(ids.size()==8&&changedScope.size()==16,\\\"native carousel membership must be complete\\\");\\n        int[] box=intRect(container),targetBox=intRect(target);\\n        JSONArray changes=new JSONArray();List<int[]> oldCover=new ArrayList<int[]>(),newCover=new ArrayList<int[]>();\\n        for(String path:a.keySet()){\\n            JSONObject x=a.get(path),y=b.get(path);\\n            if(!changedScope.contains(path)){\\n                need(!inside(path,slider)||path.equals(slider),\\\"unrecognized native carousel descendant\\\");\\n                need(WebDomCanonical.same(x,y),\\\"native target, ancestor or non-carousel node changed: \\\"+path);continue;\\n            }\\n            need(WebDomCanonical.same(without(x,\\\"bounds\\\",\\\"visible\\\"),without(y,\\\"bounds\\\",\\\"visible\\\")),\\n                    \\\"native carousel nongeometry field changed\\\");\\n            need(!x.getBoolean(\\\"editable\\\")&&!x.getBoolean(\\\"scrollable\\\")&&!x.getBoolean(\\\"password\\\")\\n                    &&!x.getBoolean(\\\"focused\\\"),\\\"carousel carries another action state\\\");\\n            if(x.getBoolean(\\\"visible\\\")){int[] r=intRect(x);need(contains(box,r),\\\"visible old carousel escaped its container\\\");oldCover.add(r);}\\n            if(y.getBoolean(\\\"visible\\\")){int[] r=intRect(y);need(contains(box,r),\\\"visible new carousel escaped its container\\\");newCover.add(r);}\\n            if(!WebDomCanonical.same(x,y))changes.put(new JSONObject().put(\\\"native_path\\\",path).put(\\\"before\\\",x).put(\\\"after\\\",y));\\n        }\\n        need(sameCoverage(oldCover,newCover,targetBox),\\\"observed carousel overlap with booking changed\\\");\\n        double cx=((double)targetBox[0]+targetBox[2])/2,cy=((double)targetBox[1]+targetBox[3])/2;\\n        need(!covered(oldCover,cx,cy)&&!covered(newCover,cx,cy),\\\"observed carousel covers the booking interior\\\");\\n        return new JSONObject().put(\\\"schema\\\",\\\"hepta.csair-home-native-scope.v1\\\")\\n                .put(\\\"scope\\\",\\\"complete_native_tree_except_observed_carousel_geometry\\\")\\n                .put(\\\"native_target_path\\\",targetPath).put(\\\"native_slider_path\\\",slider)\\n                .put(\\\"native_booking_path\\\",booking).put(\\\"before\\\",before).put(\\\"after\\\",after)\\n                .put(\\\"changes\\\",changes).put(\\\"all_non_carousel_records_equal_by_native_path\\\",true)\\n                .put(\\\"ordinal_node_ids_used_for_rebinding\\\",false)\\n                .put(\\\"existing_target_overlap_unchanged\\\",true)\\n                .put(\\\"existing_target_overlap\\\",intersections(oldCover,targetBox))\\n                .put(\\\"observed_target_interior_clear\\\",true).put(\\\"fully_unoccluded_claimed\\\",false)\\n                .put(\\\"coordinates_used_for_input\\\",false).put(\\\"business_verified\\\",false);\\n    }\\n\\n    static JSONObject compareRetained(JSONArray before,JSONArray after,String sliderPath)throws Exception{\\n        Map<String,JSONObject> a=retained(before),b=retained(after);JSONArray ordinalChanges=new JSONArray();\\n        Set<String> paths=new TreeSet<String>();paths.addAll(a.keySet());paths.addAll(b.keySet());\\n        for(String path:paths){\\n            if(path.startsWith(sliderPath+\\\"/\\\"))continue;\\n            JSONObject x=a.get(path),y=b.get(path);\\n            need(x!=null&&y!=null&&WebDomCanonical.same(without(x,\\\"id\\\"),without(y,\\\"id\\\")),\\n                    \\\"non-carousel retained native semantics or signature changed\\\");\\n            if(!x.getString(\\\"id\\\").equals(y.getString(\\\"id\\\")))ordinalChanges.put(new JSONObject()\\n                    .put(\\\"native_path\\\",path).put(\\\"original_model_node_id\\\",x.get(\\\"id\\\")).put(\\\"fresh_ordinal_node_id\\\",y.get(\\\"id\\\")));\\n        }\\n        return new JSONObject().put(\\\"all_non_carousel_records_equal_except_ordinal_id\\\",true)\\n                .put(\\\"ordinal_changes\\\",ordinalChanges).put(\\\"original_node_ref_rebound\\\",false);\\n    }\\n    private static Map<String,JSONObject> retained(JSONArray nodes)throws Exception{\\n        need(nodes!=null&&nodes.length()>0&&nodes.length()<=MAX_NATIVE_NODES,\\\"bounded retained native rows\\\");\\n        Map<String,JSONObject> out=new TreeMap<String,JSONObject>();Set<String> ids=new HashSet<String>();\\n        for(int i=0;i<nodes.length();i++){\\n            JSONObject n=nodes.getJSONObject(i);String path=n.getJSONObject(\\\"native_tree_position\\\").getString(\\\"path\\\");\\n            need(path.matches(\\\"0(?:/(?:0|[1-9][0-9]{0,5})){0,127}\\\")\\n                    &&ids.add(n.getString(\\\"id\\\"))&&out.put(path,n)==null,\\\"duplicate retained native identity\\\");\\n        }return out;\\n    }\\n    private static Map<String,JSONObject> domNodes(JSONObject dom)throws Exception{\\n        need(\\\"https://m.csair.com/\\\".equals(dom.get(\\\"href\\\"))&&\\\"complete\\\".equals(dom.get(\\\"ready_state\\\"))\\n                &&Boolean.FALSE.equals(dom.get(\\\"truncated\\\")),\\\"complete official homepage DOM required\\\");\\n        JSONArray nodes=dom.getJSONArray(\\\"nodes\\\");need(nodes.length()>0&&nodes.length()<=1024,\\\"homepage DOM budget\\\");\\n        Map<String,JSONObject> out=new TreeMap<String,JSONObject>();\\n        for(int i=0;i<nodes.length();i++){\\n            JSONObject n=nodes.getJSONObject(i);String path=n.getString(\\\"path\\\");\\n            need(path.matches(\\\"0(?:/(?:0|[1-9][0-9]{0,5})){0,127}\\\")&&out.put(path,n)==null,\\\"duplicate DOM path\\\");\\n        }\\n        return out;\\n    }\\n    private static Map<String,JSONObject> nativeNodes(JSONArray nodes)throws Exception{\\n        need(nodes!=null&&nodes.length()>0&&nodes.length()<=MAX_NATIVE_NODES,\\\"complete bounded native snapshot required\\\");\\n        Map<String,JSONObject> out=new TreeMap<String,JSONObject>();\\n        for(int i=0;i<nodes.length();i++){\\n            JSONObject n=nodes.getJSONObject(i);String path=n.getString(\\\"path\\\");\\n            need(path.matches(\\\"0(?:/(?:0|[1-9][0-9]{0,5})){0,127}\\\")\\n                    &&WebEvidenceProtocol.HELPER_PACKAGE.equals(n.get(\\\"package\\\"))\\n                    &&n.getInt(\\\"children\\\")>=0&&n.getInt(\\\"children\\\")<=MAX_NATIVE_NODES\\n                    &&out.put(path,n)==null,\\\"invalid native path/package/children\\\");\\n            int[] bounds=intRect(n);\\n            need(!n.getBoolean(\\\"visible\\\")||bounds[0]<bounds[2]&&bounds[1]<bounds[3],\\\"visible native bounds missing\\\");\\n        }\\n        need(out.containsKey(\\\"0\\\")&&out.get(\\\"0\\\").getInt(\\\"window_id\\\")>=0,\\\"actual native root missing\\\");\\n        for(Map.Entry<String,JSONObject> e:out.entrySet()){\\n            String path=e.getKey();JSONObject n=e.getValue();\\n            need(n.getInt(\\\"window_id\\\")==out.get(\\\"0\\\").getInt(\\\"window_id\\\"),\\\"mixed native windows\\\");\\n            if(!path.equals(\\\"0\\\")){JSONObject p=out.get(parent(path));need(p!=null\\n                    &&Integer.parseInt(path.substring(path.lastIndexOf('/')+1))<p.getInt(\\\"children\\\")\\n                    &&p.getString(\\\"class\\\").equals(n.getString(\\\"parent_class\\\")),\\\"native ancestor missing\\\");}\\n            for(int i=0;i<n.getInt(\\\"children\\\");i++)need(out.containsKey(path+\\\"/\\\"+i),\\\"native traversal omitted a child\\\");\\n        }\\n        return out;\\n    }\\n    private static String ancestorClass(Map<String,JSONObject> nodes,String path,String clazz)throws Exception{\\n        String p=parent(path);\\n        while(!p.isEmpty()){JSONObject n=nodes.get(p);need(n!=null,\\\"native ancestor missing\\\");\\n            if(clazz.equals(n.get(\\\"class\\\")))return p;p=parent(p);}\\n        return null;\\n    }\\n    private static JSONObject without(JSONObject value,String...keys)throws Exception{\\n        JSONObject copy=new JSONObject(WebDomCanonical.canonical(value));for(String key:keys)copy.remove(key);return copy;\\n    }\\n    private static String unique(Map<String,JSONObject> nodes,String key,String value)throws Exception{\\n        String found=null;for(Map.Entry<String,JSONObject> e:nodes.entrySet())if(value.equals(e.getValue().opt(key))){\\n            need(found==null,\\\"ambiguous \\\"+key);found=e.getKey();\\n        }need(found!=null,\\\"missing \\\"+key+\\\" \\\"+value);return found;\\n    }\\n    private static double[] rect(JSONObject n,String field)throws Exception{\\n        JSONArray r=n.getJSONArray(field);need(r.length()==4,\\\"rectangle shape\\\");double[] out=new double[4];\\n        for(int i=0;i<4;i++){Object value=r.get(i);need(value instanceof Number,\\\"numeric rectangle required\\\");\\n            out[i]=((Number)value).doubleValue();need(!Double.isNaN(out[i])&&!Double.isInfinite(out[i]),\\\"finite rectangle required\\\");}\\n        need(out[2]>=out[0]&&out[3]>=out[1],\\\"ordered rectangle required\\\");return out;\\n    }\\n    private static int[] intRect(JSONObject n)throws Exception{\\n        double[] d=rect(n,\\\"bounds\\\");int[] out=new int[4];\\n        for(int i=0;i<4;i++){need(d[i]>=Integer.MIN_VALUE&&d[i]<=Integer.MAX_VALUE&&d[i]==Math.rint(d[i]),\\\"native integer bounds required\\\");out[i]=(int)d[i];}\\n        return out;\\n    }\\n    private static boolean contains(int[] a,int[] b){return b[0]>=a[0]&&b[1]>=a[1]&&b[2]<=a[2]&&b[3]<=a[3];}\\n    private static String parent(String path){int i=path.lastIndexOf('/');return i<0?\\\"\\\":path.substring(0,i);}\\n    private static boolean inside(String path,String ancestor){return path.equals(ancestor)||path.startsWith(ancestor+\\\"/\\\");}\\n    private static String key(ActionDecision action){return action.action+\\\"\\\\n\\\"+(action.nodeId==null?\\\"\\\":action.nodeId);}\\n    private static boolean covered(List<int[]> rects,double x,double y){\\n        for(int[] r:rects)if(x>=r[0]&&x<r[2]&&y>=r[1]&&y<r[3])return true;return false;\\n    }\\n    private static boolean sameCoverage(List<int[]> before,List<int[]> after,int[] target){\\n        Set<Integer> xs=new TreeSet<Integer>(),ys=new TreeSet<Integer>();\\n        xs.add(target[0]);xs.add(target[2]);ys.add(target[1]);ys.add(target[3]);\\n        for(List<int[]> values:java.util.Arrays.asList(before,after))for(int[] r:values){\\n            xs.add(Math.max(target[0],Math.min(target[2],r[0])));xs.add(Math.max(target[0],Math.min(target[2],r[2])));\\n            ys.add(Math.max(target[1],Math.min(target[3],r[1])));ys.add(Math.max(target[1],Math.min(target[3],r[3])));\\n        }\\n        List<Integer> x=new ArrayList<Integer>(xs),y=new ArrayList<Integer>(ys);\\n        for(int i=1;i<x.size();i++)for(int j=1;j<y.size();j++){\\n            double px=((double)x.get(i-1)+x.get(i))/2,py=((double)y.get(j-1)+y.get(j))/2;\\n            if(covered(before,px,py)!=covered(after,px,py))return false;\\n        }return true;\\n    }\\n    private static JSONArray intersections(List<int[]> rects,int[] target)throws Exception{\\n        JSONArray out=new JSONArray();Set<String> seen=new HashSet<String>();\\n        for(int[] r:rects){int[] c={Math.max(r[0],target[0]),Math.max(r[1],target[1]),Math.min(r[2],target[2]),Math.min(r[3],target[3])};\\n            if(c[0]<c[2]&&c[1]<c[3]&&seen.add(java.util.Arrays.toString(c)))out.put(new JSONArray(c));}return out;\\n    }\\n    private static void need(boolean condition,String message){if(!condition)throw new IllegalArgumentException(message);}\\n}\\n\"},{\"path\":\"src/org/trillionnium/hepta/local/WebFlightSession.java\",\"base\":{\"bytes\":38651,\"sha256\":\"f50bd815470c35adf5156c81d1fdbcbaaa5f365c57fb5cd74451f610d778e158\",\"git_blob_sha\":\"965f8477f109408cef48df5017da2ec48b95b267\"},\"candidate\":{\"bytes\":42734,\"sha256\":\"7f3c7fd872e9901026ad7471dfc9a3e68d2c987eb1931896f80ea0f2acd6f4e1\",\"git_blob_sha\":\"8283d4e83b7cf13c9deb7e55c6d26f26053e11cc\"},\"ordered_patches\":[{\"before\":\"    private volatile ShoppingDispatch shoppingDispatch;\",\"after\":\"    private volatile ShoppingDispatch shoppingDispatch;\\n    private volatile WebEvidenceReceipt currentCapture;\\n    private volatile WebFlightNativeStability.Permit flightNativePermit;\\n    private volatile HeptaAccessibilityService.FlightNativeCheck flightNativeCheck;\\n    private final java.util.concurrent.atomic.AtomicBoolean flightNativeEntered=new java.util.concurrent.atomic.AtomicBoolean();\",\"count\":1},{\"before\":\"        current=after;domain=observed;completion.bindWebDomain(observed);\",\"after\":\"        current=after;currentCapture=last;domain=observed;completion.bindWebDomain(observed);\\n        flightNativePermit=null;flightNativeCheck=null;\",\"count\":1},{\"before\":\"        current=frame;domain=waiting;completion.bindWebDomain(waiting);\",\"after\":\"        current=frame;currentCapture=null;domain=waiting;completion.bindWebDomain(waiting);\\n        flightNativePermit=null;flightNativeCheck=null;\",\"count\":1},{\"before\":\"        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;shoppingDispatch=null;\\n        if(\\\"wait\\\".equals(action.action)\",\"after\":\"        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;shoppingDispatch=null;\\n        flightNativePermit=null;flightNativeCheck=null;flightNativeEntered.set(false);\\n        if(\\\"wait\\\".equals(action.action)\",\"count\":1},{\"before\":\"        rechecked.requireCurrent(action);\\n        if(rechecked.shopping!=null\",\"after\":\"        rechecked.requireCurrent(action);\\n        flightNativePermit=WebFlightNativeStability.prepare(rechecked,frame,action,run,currentCapture,fresh);\\n        if(rechecked.shopping!=null\",\"count\":1},{\"before\":\"                .put(\\\"unchanged_semantic_region\\\",true).put(\\\"whole_dom_equality_claimed\\\",false)\",\"after\":\"                .put(\\\"unchanged_semantic_region\\\",true).put(\\\"whole_dom_equality_claimed\\\",false)\\n                .put(\\\"flight_home_native_stability_scope\\\",flightNativePermit==null?JSONObject.NULL:flightNativePermit.domEvidence())\",\"count\":1},{\"before\":\"                dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;shoppingDispatch=null;\\n            }\",\"after\":\"                dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;shoppingDispatch=null;\\n                flightNativePermit=null;flightNativeCheck=null;\\n            }\",\"count\":1},{\"before\":\"    WebRegionNativeBridge nativeRegionForDispatch(ActionDecision action,String run,PhoneObservation frame){\",\"after\":\"    WebFlightNativeStability.Permit flightNativePermitForDispatch(ActionDecision action,PhoneObservation frame){\\n        WebFlightNativeStability.Permit permit=flightNativePermit;\\n        if(permit==null)return null;\\n        requireDispatch(action,dispatchCheckedRun);\\n        need(!cancellation.isCancelled()&&permit.matches(frame,action,dispatchCheckedRun)\\n                &&frame==current&&!flightNativeEntered.get(),\\\"exact unconsumed homepage booking dispatch required\\\");\\n        return permit;\\n    }\\n    void acceptFlightNativeCheck(ActionDecision action,PhoneObservation frame,HeptaAccessibilityService.FlightNativeCheck check)throws Exception{\\n        WebFlightNativeStability.Permit permit=flightNativePermitForDispatch(action,frame);\\n        need(permit!=null&&check!=null&&check.matches(frame,permit)&&flightNativeCheck==null,\\n                \\\"one actual native homepage check required\\\");\\n        // Preserve the complete actual source/fresh snapshots and their exact\\n        // differences before the platform call. This record grants no input API.\\n        record(\\\"web-flight-native-stability-\\\"+permit.run+\\\".json\\\",check.evidence());\\n        flightNativeCheck=check;\\n    }\\n    WebRegionNativeBridge nativeRegionForDispatch(ActionDecision action,String run,PhoneObservation frame){\",\"count\":1},{\"before\":\"        WebTaskDomain source=dispatchSource,currentDomain=domain;\\n        if(purpose.shopping!=null\",\"after\":\"        WebTaskDomain source=dispatchSource,currentDomain=domain;\\n        WebFlightNativeStability.Permit permit=flightNativePermit;\\n        if(permit!=null){\\n            requireDispatch(action,run);\\n            HeptaAccessibilityService.FlightNativeCheck check=flightNativeCheck;long now=SystemClock.elapsedRealtime();\\n            need(permit.matches(current,action,run)&&check!=null&&check.matches(current,permit)\\n                    &&check.checkedAt<=now&&now-check.checkedAt<=250\\n                    &&flightNativeEntered.compareAndSet(false,true),\\n                    \\\"booking native check expired, mismatched or already consumed\\\");\\n        }\\n        if(purpose.shopping!=null\",\"count\":1},{\"before\":\"            dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;shoppingDispatch=null;\\n        }\\n    }\\n    private WebTaskDomain applyNavigation\",\"after\":\"            dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;shoppingDispatch=null;\\n            flightNativePermit=null;flightNativeCheck=null;\\n        }\\n    }\\n    private WebTaskDomain applyNavigation\",\"count\":1},{\"before\":\"    void serviceRetired(){retired=true;domain=null;pendingNavigation=null;shoppingNavigation=null;dispatchSource=null;shoppingDispatch=null;\",\"after\":\"    void serviceRetired(){retired=true;domain=null;currentCapture=null;flightNativePermit=null;flightNativeCheck=null;pendingNavigation=null;shoppingNavigation=null;dispatchSource=null;shoppingDispatch=null;\",\"count\":1},{\"before\":\"        retired=true;domain=null;pendingNavigation=null;shoppingNavigation=null;dispatchSource=null;shoppingDispatch=null;\\n        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;completion.clearWebDomain();\",\"after\":\"        retired=true;domain=null;currentCapture=null;flightNativePermit=null;flightNativeCheck=null;pendingNavigation=null;shoppingNavigation=null;dispatchSource=null;shoppingDispatch=null;\\n        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;completion.clearWebDomain();\",\"count\":1},{\"before\":\"    private final java.util.concurrent.atomic.AtomicBoolean flightNativeEntered=new java.util.concurrent.atomic.AtomicBoolean();\",\"after\":\"    private final java.util.concurrent.atomic.AtomicBoolean flightNativeEntered=new java.util.concurrent.atomic.AtomicBoolean();\\n    private final java.util.Set<String> flightNativeAttemptedRuns=java.util.Collections.synchronizedSet(new java.util.HashSet<String>());\",\"count\":1},{\"before\":\"        flightNativePermit=WebFlightNativeStability.prepare(rechecked,frame,action,run,currentCapture,fresh);\",\"after\":\"        flightNativePermit=WebFlightNativeStability.prepare(rechecked,frame,action,run,currentCapture,fresh);\\n        if(flightNativePermit!=null)need(!flightNativeAttemptedRuns.contains(run)&&flightNativeAttemptedRuns.size()<64,\\n                \\\"booking invocation for this model run is already consumed or its bounded attempt budget is full\\\");\",\"count\":1},{\"before\":\"                    &&flightNativeEntered.compareAndSet(false,true),\",\"after\":\"                    &&flightNativeEntered.compareAndSet(false,true)&&flightNativeAttemptedRuns.add(run),\",\"count\":1},{\"before\":\"    Cleanup close(String reason){\\n        retired=true;domain=null;currentCapture=null;flightNativePermit=null;flightNativeCheck=null;pendingNavigation=null;shoppingNavigation=null;dispatchSource=null;shoppingDispatch=null;\\n        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;completion.clearWebDomain();\\n        try{\\n            if(!journal.attachWasPrepared()){\\n                journal.closeNeverAttached();cleanupKnown=true;\\n                return new Cleanup(true,new JSONObject().put(\\\"cleanup_known\\\",true).put(\\\"no_attach_request_prepared\\\",true)\\n                        .put(\\\"task_id\\\",taskId).put(\\\"binding_sha256\\\",journal.bindingSha));\\n            }\\n            WebEvidenceReceipt proof=client.closeLease(reason,SystemClock.elapsedRealtime()+10000);\\n            journal.closeKnown(proof);cleanupKnown=true;\\n            return new Cleanup(true,new JSONObject().put(\\\"cleanup_known\\\",true).put(\\\"helper\\\",proof.callback())\\n                    .put(\\\"task_id\\\",taskId).put(\\\"binding_sha256\\\",journal.bindingSha).put(\\\"business_verified\\\",false));\\n        }catch(Exception unknown){\\n            try{return new Cleanup(false,new JSONObject().put(\\\"cleanup_known\\\",false).put(\\\"task_id\\\",taskId)\\n                    .put(\\\"binding_sha256\\\",journal.bindingSha).put(\\\"error\\\",HeptaAccessibilityService.limited(HeptaAccessibilityService.message(unknown),512))\\n                    .put(\\\"automatic_retry\\\",false));}catch(Exception impossible){throw new IllegalStateException(impossible);}\\n        }finally{client.close();}\\n    }\\n\",\"after\":\"    Cleanup close(String reason){\\n        TaskCompletionGate.WebCloseAttempt completionClose=completion.beginWebClose(this,domain,taskId,journal.bindingSha,reason);\\n        boolean closeReturnedNormally=false;\\n        retired=true;domain=null;currentCapture=null;flightNativePermit=null;flightNativeCheck=null;pendingNavigation=null;shoppingNavigation=null;dispatchSource=null;shoppingDispatch=null;\\n        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;completion.clearWebDomain();\\n        try{\\n            if(!journal.attachWasPrepared()){\\n                journal.closeNeverAttached();cleanupKnown=true;\\n                return new Cleanup(true,new JSONObject().put(\\\"cleanup_known\\\",true).put(\\\"no_attach_request_prepared\\\",true)\\n                        .put(\\\"task_id\\\",taskId).put(\\\"binding_sha256\\\",journal.bindingSha));\\n            }\\n            WebEvidenceReceipt proof=client.closeLease(reason,SystemClock.elapsedRealtime()+10000);\\n            journal.closeKnown(proof);cleanupKnown=true;\\n            JSONObject actualCallback=proof.callback();\\n            Cleanup known=new Cleanup(true,new JSONObject().put(\\\"cleanup_known\\\",true).put(\\\"helper\\\",actualCallback)\\n                    .put(\\\"task_id\\\",taskId).put(\\\"binding_sha256\\\",journal.bindingSha).put(\\\"business_verified\\\",false));\\n            if(proof.cleanupKnown&&!proof.recovered&&!proof.unstarted)\\n                completion.webCloseKnown(completionClose,this,actualCallback.getString(\\\"task_id\\\"),proof.bindingSha,\\n                        proof.status,proof.instance,proof.epoch,proof.displayId,proof.windowId,\\n                        WebEvidenceJson.sha(WebDomCanonical.canonical(actualCallback)));\\n            else completion.abortWebClose(completionClose);\\n            closeReturnedNormally=true;return known;\\n        }catch(Exception unknown){\\n            try{return new Cleanup(false,new JSONObject().put(\\\"cleanup_known\\\",false).put(\\\"task_id\\\",taskId)\\n                    .put(\\\"binding_sha256\\\",journal.bindingSha).put(\\\"error\\\",HeptaAccessibilityService.limited(HeptaAccessibilityService.message(unknown),512))\\n                    .put(\\\"automatic_retry\\\",false));}catch(Exception impossible){throw new IllegalStateException(impossible);}\\n        }finally{\\n            if(!closeReturnedNormally)completion.abortWebClose(completionClose);\\n            client.close();\\n        }\\n    }\\n\",\"count\":1}]},{\"path\":\"src/org/trillionnium/hepta/local/WebShoppingDomain.java\",\"base\":{\"bytes\":31708,\"sha256\":\"c1c564118915d230d2b5c9ff275c05263b9253e3c876d03db7b63a5a76248aa0\",\"git_blob_sha\":\"da3880029d43376cd271df68517675615c2800bd\"},\"candidate\":{\"bytes\":31717,\"sha256\":\"bbf256e37eb5cc3a1619371e9c29dc5f7af3139eeb4f602f602cf0f05551bf92\",\"git_blob_sha\":\"78c1c4d616a815dbf31b214f0fb74754745c967c\"},\"ordered_patches\":[{\"before\":\"proof.put(\\\"native_geometry\\\",geometry==null?null:geometry.evidence());\",\"after\":\"proof.put(\\\"native_geometry\\\",geometry==null?null:jsonMap(geometry.evidence()));\",\"count\":1}]},{\"path\":\"tests/completion/TaskCompletionGateHostTest.java\",\"base\":{\"bytes\":28547,\"sha256\":\"6d34fc64d4d42b76d9760993cc725453dc24122361e2a9ef6937dfa4c0851286\",\"git_blob_sha\":\"9c363c22ff6d1eb0e80017588af7532e4329f8fc\"},\"candidate\":{\"bytes\":28781,\"sha256\":\"d86c0ea22722de346ab092a9d479e169fc66febb8daf14dfc0a5ec060c0614d8\",\"git_blob_sha\":\"56d26ecf8d13f7ce03004e922a5f275ee4083354\"},\"ordered_patches\":[{\"before\":\"        public TaskCleanup endTask(){\\n            ends++;\\n\",\"after\":\"        public TaskCleanup endTask(){\\n            ends++;\\n            if(\\\"close_cancelled\\\".equals(mode))e.controller.stop();\\n\",\"count\":1},{\"before\":\":\\\"cancel\\\".equals(mode)?\\\"cancelled\\\":\",\"after\":\":(\\\"cancel\\\".equals(mode)||\\\"close_cancelled\\\".equals(mode))?\\\"cancelled\\\":\",\"count\":1},{\"before\":\"        test(\\\"actual_controller_bad_native_close_receipt_cannot_complete\\\",()->controllerCase(\\\"close_invalid_receipt\\\",OWNER,false,2));\\n\",\"after\":\"        test(\\\"actual_controller_bad_native_close_receipt_cannot_complete\\\",()->controllerCase(\\\"close_invalid_receipt\\\",OWNER,false,2));\\n        test(\\\"actual_controller_cancel_during_worker_teardown_cannot_complete\\\",()->controllerCase(\\\"close_cancelled\\\",OWNER,false,2));\\n\",\"count\":1}]},{\"path\":\"tests/qualification-scope/BackgroundObservationFixture.template\",\"base\":{\"bytes\":2286,\"sha256\":\"9a6804870db383738c206db711359dbd852db9632a4d8e82635d34125d6c68ca\",\"git_blob_sha\":\"f0a7befce4b4c8390b50d6d9a83695a8cc60a5e2\"},\"candidate\":{\"bytes\":2313,\"sha256\":\"f5655ba51cfe217cfe4dcaf759d6bd58e7ec87f4a40dde7d2ba9ada23d62c3a6\",\"git_blob_sha\":\"a739a4ba9c8d3ece8bae07cba6f6582a625598d0\"},\"ordered_patches\":[{\"before\":\"import org.json.JSONObject;\\n\",\"after\":\"import org.json.JSONObject;\\nimport org.json.JSONArray;\\n\",\"count\":1}]},{\"path\":\"tests/qualification-scope/ServiceFixture.template\",\"base\":{\"bytes\":7641,\"sha256\":\"1833ce5c0d51445497aebcd578d2c005a8a03ac5c265c5842e8e8738e6dd49ab\",\"git_blob_sha\":\"f547d6c0a4648327917e10dcdbf74960d58abfb1\"},\"candidate\":{\"bytes\":8230,\"sha256\":\"0b6b4d0986691ffc328f89f17b74ab055385f13b437acd562633ad1fca8532d2\",\"git_blob_sha\":\"ad37011ca74b6c3bcb34687bff3e261a2858e6c0\"},\"ordered_patches\":[{\"before\":\"    static HeptaAccessibilityService live;\\n\",\"after\":\"    /** Type-only legacy boundary; never a successful Flight native-stability recheck. */\\n    static final class FlightNativeCheck {\\n        private FlightNativeCheck(){throw new AssertionError(\\\"legacy fixture has no Flight native-stability evidence\\\");}\\n    }\\n    private FlightNativeCheck requireLiveFlightNativeStability(String taskId,PhoneObservation frame,ActionDecision action,\\n            WebFlightNativeStability.Permit permit,Graph now,Cancellation cancel)throws Exception{\\n        throw new AssertionError(\\\"legacy fixture cannot execute a Flight native-stability recheck\\\");\\n    }\\n    static HeptaAccessibilityService live;\\n\",\"count\":1}]},{\"path\":\"tests/qualification-scope/fixtures/org/trillionnium/hepta/local/WebFlightSession.java\",\"base\":{\"bytes\":3353,\"sha256\":\"92c20a04bcc578e3154cf11717682e4c4ad46eaff5e72c57fe441f7e4df55615\",\"git_blob_sha\":\"612e1da1aa0774d57b891d04fa1ade97a46d529b\"},\"candidate\":{\"bytes\":3684,\"sha256\":\"1bf4db123f478cd2285fcdd146e7cc07d31d64a9343a96766054188e64dc46e5\",\"git_blob_sha\":\"4ef37e5ce29f49632b7e93d4bf32bea293c259bc\"},\"ordered_patches\":[{\"before\":\"    final String taskId;\\n\",\"after\":\"    final String taskId;\\n    final WebFlightGoal goal;\\n\",\"count\":1},{\"before\":\"    WebRegionNativeBridge nativeRegionForDispatch(ActionDecision action,String run,PhoneObservation frame){throw unavailable();}\\n\",\"after\":\"    WebFlightNativeStability.Permit flightNativePermitForDispatch(ActionDecision action,PhoneObservation frame){throw unavailable();}\\n    void acceptFlightNativeCheck(ActionDecision action,PhoneObservation frame,HeptaAccessibilityService.FlightNativeCheck check)throws Exception{throw unavailable();}\\n    WebRegionNativeBridge nativeRegionForDispatch(ActionDecision action,String run,PhoneObservation frame){throw unavailable();}\\n\",\"count\":1}]},{\"path\":\"tests/qualification-scope/prepare_fixture.py\",\"base\":{\"bytes\":10806,\"sha256\":\"ea087c1923ed205f5f0a39bfc0bc1e02b63fa2c72ec8fab7e73ebe2bdf628fdf\",\"git_blob_sha\":\"7cf2b077e9e6558d9c2d03fa8e0cdc40b7a333a0\"},\"candidate\":{\"bytes\":11439,\"sha256\":\"3e259c4796752dd955df4a1bc8e9e16587c147c70f2d79f8755af2243140d00c\",\"git_blob_sha\":\"667293678cd99beeabf82a6ae0965bdc3b137a25\"},\"ordered_patches\":[{\"before\":\"        'snapshot': section(s, '    /** A background root comes only', '    private static String nodeSignature('),\",\"after\":\"        'snapshot': section(s, '    /** A background root comes only', '    private FlightNativeCheck requireLiveFlightNativeStability('),\",\"count\":1},{\"before\":\"    session = (pkg / 'LocalTaskSession.java').read_text()\\n\",\"after\":\"    (output/'WebFlightNativeStability.java').write_text(\\\"package org.trillionnium.hepta.local;\\\\n/** Type-only legacy non-Web boundary. No Flight stability permit can be created. */\\\\nfinal class WebFlightNativeStability {\\\\n    static final int MAX_NATIVE_NODES=512;\\\\n    private WebFlightNativeStability(){throw new AssertionError(\\\\\\\"legacy fixture has no Flight native-stability capability\\\\\\\");}\\\\n    static final class Permit {\\\\n        private Permit(){throw new AssertionError(\\\\\\\"legacy fixture has no Flight native-stability permit\\\\\\\");}\\\\n    }\\\\n}\\\\n\\\")\\n    session = (pkg / 'LocalTaskSession.java').read_text()\\n\",\"count\":1},{\"before\":\"        'web_native_fixture_boundary':'The original complete dispatch branch is retained; WebRegionNativeBridge, NativeRegionCheck and both WebSession native-region endpoints are throwing type-only boundaries',\",\"after\":\"        'web_native_fixture_boundary':'The original complete dispatch branch is retained; WebRegionNativeBridge, NativeRegionCheck, FlightNativeCheck, WebFlightNativeStability.Permit and the WebSession native-region/Flight endpoints are throwing type-only boundaries',\",\"count\":1}]},{\"path\":\"tests/warm-finalization/prepare_fixture.py\",\"base\":{\"git_blob_sha\":\"07785c82038007af91ba6612d410df5e96d143b2\",\"bytes\":5713,\"sha256\":\"ae5bccaf044adfb755de0555fdff7d511254a399fb904dc5f103b5a8a36f5bb9\"},\"candidate\":{\"bytes\":6220,\"sha256\":\"e4ee5ea79e689a2e89d64f5c8092a523e77ab5a337c5965c34a32974d06092e1\",\"git_blob_sha\":\"b55a5e693c29035d94e1140c77b299f8fce56d1c\"},\"ordered_patches\":[{\"before\":\"    private volatile boolean running=true,blocked;\",\"after\":\"    private volatile boolean running=true,blocked,terminalDecisionSealed;\",\"count\":1},{\"before\":\"    /** Admitted/live Owner authorization seam; actual admission runs in the controller harness. */\\n    private interface AuthorizationFrame { boolean successAllowed(); }\\n    private interface AuthorizationCheck { void ready(); AuthorizationFrame frame(); }\\n    private final AuthorizationCheck authorization=new AuthorizationCheck(){\\n        public void ready(){}\\n        public AuthorizationFrame frame(){throw new AssertionError(\\\"legacy fixture has no controller-workflow candidate\\\");}\\n    };\",\"after\":\"    /** Type-only Owner boundary; this legacy fixture cannot create an authorized Frame. */\\n    private static final class TaskAuthorization {\\n        private interface Frame { boolean successAllowed(); }\\n    }\\n    private interface AuthorizationCheck { void ready(); TaskAuthorization.Frame frame(); }\\n    private final AuthorizationCheck authorization=new AuthorizationCheck(){\\n        public void ready(){}\\n        public TaskAuthorization.Frame frame(){throw new AssertionError(\\\"legacy fixture has no controller-workflow candidate\\\");}\\n    };\\n    /** Explicit non-Web contract; no helper close proof or Web completion is provided. */\\n    private static final class TaskCompletionGate {\\n        private static final String WEB=\\\"web_search_results\\\";\\n        private static final class Contract { private final String kind=\\\"unverified_goal\\\"; }\\n        private final Contract contract=new Contract();\\n    }\\n    private final TaskCompletionGate completion=new TaskCompletionGate();\",\"count\":1}]},{\"path\":\"tests/web-flight/run_query_host_tests.py\",\"base\":{\"bytes\":40095,\"sha256\":\"18ad7e7a2a3da8e8953128c7ca3105a9b81ae3edd6df975c177106a37e7cfd53\",\"git_blob_sha\":\"6cba08c6e2968107b054c5271065407261cf4016\"},\"candidate\":{\"bytes\":41005,\"sha256\":\"0f4d983138ed8bcf5f0b622ee4d4063048e83413eafe3586595521f5e1b7eb45\",\"git_blob_sha\":\"7b7a23db9302bc63b71f51a4d74d06c34183059d\"},\"ordered_patches\":[{\"before\":\"PURE_PATHS=[\\\"src/org/trillionnium/hepta/background/FixedIntentTarget.java\\\",\\\"src/org/trillionnium/hepta/background/FixedIntentTools.java\\\",\\\"src/org/trillionnium/hepta/local/ActionDecision.java\\\",\\\"src/org/trillionnium/hepta/local/AppCatalogueRanker.java\\\",\\\"src/org/trillionnium/hepta/local/CsairCityPicker.java\\\",\\\"src/org/trillionnium/hepta/local/CsairFlightForm.java\\\",\\\"src/org/trillionnium/hepta/local/DecisionGrammar.java\\\",\\\"src/org/trillionnium/hepta/local/ImeVisibility.java\\\",\\\"src/org/trillionnium/hepta/local/MiPublicProductPage.java\\\",\\\"src/org/trillionnium/hepta/local/NotesCompletionEvidence.java\\\",\\\"src/org/trillionnium/hepta/local/NotesCreateWorkflow.java\\\",\\\"src/org/trillionnium/hepta/local/NotesOwnerIntent.java\\\",\\\"src/org/trillionnium/hepta/local/ObservationState.java\\\",\\\"src/org/trillionnium/hepta/local/ObservedAppLabels.java\\\",\\\"src/org/trillionnium/hepta/local/ObservedChildText.java\\\",\\\"src/org/trillionnium/hepta/local/ObservedImeEnter.java\\\",\\\"src/org/trillionnium/hepta/local/ObservedScrollActions.java\\\",\\\"src/org/trillionnium/hepta/local/ObservedTargetLabels.java\\\",\\\"src/org/trillionnium/hepta/local/ObservedWindowMetadata.java\\\",\\\"src/org/trillionnium/hepta/local/PhoneObservation.java\\\",\\\"src/org/trillionnium/hepta/local/TaskAuthorization.java\\\",\\\"src/org/trillionnium/hepta/local/TaskCompletionGate.java\\\",\\\"src/org/trillionnium/hepta/local/WebEvidenceJson.java\\\",\\\"src/org/trillionnium/hepta/local/WebEvidenceReceipt.java\\\",\\\"src/org/trillionnium/hepta/local/WebFlightDomain.java\\\",\\\"src/org/trillionnium/hepta/local/WebNativeGeometry.java\\\",\\\"src/org/trillionnium/hepta/local/WebShoppingDomain.java\\\",\\\"src/org/trillionnium/hepta/local/WebTaskDomain.java\\\",\\\"src/org/trillionnium/hepta/local/web/WebFlightGoal.java\\\",\\\"src/org/trillionnium/hepta/local/web/WebShoppingGoal.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebEvidenceBinding.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebRecoveryPolicy.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebSitePolicy.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebStorageEvidence.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebTaskPurpose.java\\\",\\\"src/org/trillionnium/hepta/local/CsairCalendar.java\\\",\\\"src/org/trillionnium/hepta/local/WebFlightProgress.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebDomCanonical.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebDomStability.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebMiActionRegion.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebObservedNavigation.java\\\",\\\"src/org/trillionnium/hepta/local/WebRegionNativeBridge.java\\\",\\\"tests/qualification-scope/fixtures/android/graphics/Rect.java\\\",\\\"tests/web-flight/WebFlightQueryHostTest.java\\\"]\",\"after\":\"PURE_PATHS=[\\\"src/org/trillionnium/hepta/background/FixedIntentTarget.java\\\",\\\"src/org/trillionnium/hepta/background/FixedIntentTools.java\\\",\\\"src/org/trillionnium/hepta/local/ActionDecision.java\\\",\\\"src/org/trillionnium/hepta/local/AppCatalogueRanker.java\\\",\\\"src/org/trillionnium/hepta/local/CsairCityPicker.java\\\",\\\"src/org/trillionnium/hepta/local/CsairFlightForm.java\\\",\\\"src/org/trillionnium/hepta/local/DecisionGrammar.java\\\",\\\"src/org/trillionnium/hepta/local/ImeVisibility.java\\\",\\\"src/org/trillionnium/hepta/local/MiPublicProductPage.java\\\",\\\"src/org/trillionnium/hepta/local/NotesCompletionEvidence.java\\\",\\\"src/org/trillionnium/hepta/local/NotesCreateWorkflow.java\\\",\\\"src/org/trillionnium/hepta/local/NotesOwnerIntent.java\\\",\\\"src/org/trillionnium/hepta/local/ObservationState.java\\\",\\\"src/org/trillionnium/hepta/local/ObservedAppLabels.java\\\",\\\"src/org/trillionnium/hepta/local/ObservedChildText.java\\\",\\\"src/org/trillionnium/hepta/local/ObservedImeEnter.java\\\",\\\"src/org/trillionnium/hepta/local/ObservedScrollActions.java\\\",\\\"src/org/trillionnium/hepta/local/ObservedTargetLabels.java\\\",\\\"src/org/trillionnium/hepta/local/ObservedWindowMetadata.java\\\",\\\"src/org/trillionnium/hepta/local/PhoneObservation.java\\\",\\\"src/org/trillionnium/hepta/local/TaskAuthorization.java\\\",\\\"src/org/trillionnium/hepta/local/TaskCompletionGate.java\\\",\\\"src/org/trillionnium/hepta/local/WebEvidenceJson.java\\\",\\\"src/org/trillionnium/hepta/local/WebEvidenceReceipt.java\\\",\\\"src/org/trillionnium/hepta/local/WebFlightDomain.java\\\",\\\"src/org/trillionnium/hepta/local/WebFlightNativeStability.java\\\",\\\"src/org/trillionnium/hepta/local/WebNativeGeometry.java\\\",\\\"src/org/trillionnium/hepta/local/WebShoppingDomain.java\\\",\\\"src/org/trillionnium/hepta/local/WebTaskDomain.java\\\",\\\"src/org/trillionnium/hepta/local/web/WebFlightGoal.java\\\",\\\"src/org/trillionnium/hepta/local/web/WebShoppingGoal.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebEvidenceBinding.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebRecoveryPolicy.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebSitePolicy.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebStorageEvidence.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebTaskPurpose.java\\\",\\\"src/org/trillionnium/hepta/local/CsairCalendar.java\\\",\\\"src/org/trillionnium/hepta/local/WebFlightProgress.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebDomCanonical.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebDomStability.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebMiActionRegion.java\\\",\\\"src/org/trillionnium/hepta/webprotocol/WebObservedNavigation.java\\\",\\\"src/org/trillionnium/hepta/local/WebRegionNativeBridge.java\\\",\\\"tests/qualification-scope/fixtures/android/graphics/Rect.java\\\",\\\"tests/web-flight/WebFlightQueryHostTest.java\\\"]\",\"count\":1},{\"before\":\"PROJECTION=\\\"package org.trillionnium.hepta.local;\\\\nimport org.json.JSONObject;\\\\nimport org.trillionnium.hepta.webprotocol.WebTaskPurpose;\\\\n/** Unit projection: the exact production Session methods are inserted below.\\\\n * Clock/outcome and writer are host boundaries; shopping-only type endpoints always throw. */\\\\nfinal class WebFlightDispatchProjection {\\\\n    private WebTaskDomain domain,dispatchSource;\\\\n    private WebTaskPurpose purpose;\\\\n    private PhoneObservation current;\\\\n    private String taskId;\\\\n    private ShoppingDispatch shoppingDispatch;\\\\n    private Journal journal;\\\\n    /** Shopping-only type endpoints. These fixtures cannot create an ARM or native token. */\\\\n    private static final class Journal{\\\\n        String bindingSha;\\\\n        private Journal(){throw new UnsupportedOperationException(\\\\\\\"query-only journal type\\\\\\\");}\\\\n    }\\\\n    private static final class ShoppingDispatch{\\\\n        WebRegionNativeBridge bridge;\\\\n        String run,actionKey,armRaw;\\\\n        java.util.concurrent.atomic.AtomicBoolean entered;\\\\n        long enteredAt,expiresAt;\\\\n        HeptaAccessibilityService.NativeRegionCheck liveNative;\\\\n        private ShoppingDispatch(){throw new UnsupportedOperationException(\\\\\\\"query-only shopping type\\\\\\\");}\\\\n    }\\\\n    private ShoppingDispatch requireShoppingDispatch(ActionDecision action,String run){\\\\n        throw new UnsupportedOperationException(\\\\\\\"shopping dispatch is outside this flight gate\\\\\\\");\\\\n    }\\\\n    private String dispatchSourceRun,dispatchSourceAction,dispatchCheckedRun,dispatchCheckedAction;\\\\n    private long dispatchCheckedAt;\\\\n    private boolean retired,failRecord;\\\\n    private WebFlightProgress flightProgress;\\\\n    private final java.util.concurrent.atomic.AtomicBoolean nativeQueryEntered=new java.util.concurrent.atomic.AtomicBoolean();\\\\n    private WebShoppingDomain.Navigation shoppingNavigation;\\\\n    private PendingNavigation pendingNavigation;\\\\n    private static final class SystemClock {static long elapsedRealtime(){return 1120;}}\\\\n    private static final class HeptaAccessibilityService {\\\\n        private static final class NativeRegionCheck{\\\\n            long checkedAt;\\\\n            private NativeRegionCheck(){throw new UnsupportedOperationException(\\\\\\\"native token cannot be constructed in this gate\\\\\\\");}\\\\n            boolean matches(PhoneObservation frame,WebRegionNativeBridge bridge){\\\\n                throw new UnsupportedOperationException(\\\\\\\"native check is outside this flight gate\\\\\\\");\\\\n            }\\\\n            JSONObject evidence()throws Exception{\\\\n                throw new UnsupportedOperationException(\\\\\\\"native evidence is outside this flight gate\\\\\\\");\\\\n            }\\\\n        }\\\\n        static final class ActionOutcome{\\\\n            final boolean accepted,dispatched,stale;\\\\n            ActionOutcome(boolean a,boolean d,boolean s){accepted=a;dispatched=d;stale=s;}\\\\n        }\\\\n    }\\\\n    private void record(String name,JSONObject evidence)throws Exception{\\\\n        if(failRecord)throw new java.io.IOException(\\\\\\\"synthetic evidence writer failure\\\\\\\");\\\\n        if(name==null||evidence==null)throw new AssertionError(\\\\\\\"record arguments\\\\\\\");\\\\n    }\\\\n    private static void need(boolean yes,String reason){WebEvidenceJson.need(yes,reason);}\\\\n    /* EXACT_METHODS */\\\\n    private interface Work{void run()throws Exception;}\\\\n    private static void rejects(Work body)throws Exception{\\\\n        boolean refused=false;try{body.run();}catch(IllegalArgumentException|IllegalStateException|java.io.IOException expected){refused=true;}\\\\n        if(!refused)throw new AssertionError(\\\\\\\"actual production dispatch method accepted a duplicate or missing source\\\\\\\");\\\\n    }\\\\n    static boolean verify(WebTaskDomain d,WebFlightProgress p,ActionDecision action,String run,int scenario)throws Exception{\\\\n        WebFlightDispatchProjection f=new WebFlightDispatchProjection();\\\\n        f.domain=d;f.dispatchSource=d;f.dispatchSourceRun=run;f.dispatchSourceAction=actionKey(action);\\\\n        f.purpose=WebTaskPurpose.fromOwner(d.flight.goal.immutableOwner);f.taskId=d.taskId;\\\\n        need(f.purpose.flight!=null,\\\\\\\"the retained query scenarios require the actual flight purpose\\\\\\\");\\\\n        f.dispatchCheckedRun=run;f.dispatchCheckedAction=actionKey(action);f.dispatchCheckedAt=1111;\\\\n        f.flightProgress=p.reserveQuery(d.flight,action,run);\\\\n        if(scenario==0){\\\\n            // The service deliberately rechecks authorization twice before its one platform call.\\\\n            f.requireDispatch(action,run);f.requireDispatch(action,run);\\\\n            f.beforeNativeClickInvocation(action,run);\\\\n            rejects(()->f.beforeNativeClickInvocation(action,run));\\\\n        }else if(scenario==1||scenario==2){\\\\n            f.requireDispatch(action,run);f.beforeNativeClickInvocation(action,run);\\\\n            f.modelActionOutcome(action,run,new HeptaAccessibilityService.ActionOutcome(scenario==1,scenario==1,false),1112,1115);\\\\n            rejects(()->f.requireDispatch(action,run));\\\\n            rejects(()->f.beforeNativeClickInvocation(action,run));\\\\n            if(f.dispatchSource!=null||f.dispatchCheckedRun!=null||f.dispatchCheckedAction!=null||f.dispatchCheckedAt!=0)\\\\n                throw new AssertionError(\\\\\\\"original outcome must retire the dispatch capability even when false\\\\\\\");\\\\n        }else if(scenario==3){\\\\n            f.beforeNativeClickInvocation(action,run);f.failRecord=true;\\\\n            rejects(()->f.modelActionOutcome(action,run,new HeptaAccessibilityService.ActionOutcome(true,true,false),1112,1115));\\\\n            rejects(()->f.requireDispatch(action,run));rejects(()->f.beforeNativeClickInvocation(action,run));\\\\n        }else if(scenario==4){\\\\n            f.beforeNativeClickInvocation(action,run);\\\\n            rejects(()->f.modelActionOutcome(action,\\\\\\\"00000000000000000000000000000000\\\\\\\",\\\\n                    new HeptaAccessibilityService.ActionOutcome(true,true,false),1112,1115));\\\\n            rejects(()->f.requireDispatch(action,run));rejects(()->f.beforeNativeClickInvocation(action,run));\\\\n        }else if(scenario==5){\\\\n            f.dispatchSource=null;\\\\n            rejects(()->f.beforeNativeClickInvocation(action,run));\\\\n        }else if(scenario==6){\\\\n            f.dispatchSourceAction=\\\\\\\"click\\\\\\\\nforeign\\\\\\\";\\\\n            rejects(()->f.beforeNativeClickInvocation(action,run));\\\\n            if(f.nativeQueryEntered.get())throw new AssertionError(\\\\\\\"wrong action consumed platform gate\\\\\\\");\\\\n        }else if(scenario==7){\\\\n            f.dispatchCheckedRun=null;f.dispatchCheckedAction=null;f.dispatchCheckedAt=0;\\\\n            rejects(()->f.requireDispatch(action,run));\\\\n        }else throw new AssertionError(\\\\\\\"unknown projection case\\\\\\\");\\\\n        return true;\\\\n    }\\\\n}\\\\n\\\"\",\"after\":\"PROJECTION=\\\"package org.trillionnium.hepta.local;\\\\nimport org.json.JSONObject;\\\\nimport org.trillionnium.hepta.webprotocol.WebTaskPurpose;\\\\n/** Unit projection: the exact production Session methods are inserted below.\\\\n * Clock/outcome and writer are host boundaries; shopping-only type endpoints always throw. */\\\\nfinal class WebFlightDispatchProjection {\\\\n    private WebTaskDomain domain,dispatchSource;\\\\n    private WebTaskPurpose purpose;\\\\n    private PhoneObservation current;\\\\n    private String taskId;\\\\n    private ShoppingDispatch shoppingDispatch;\\\\n    private WebFlightNativeStability.Permit flightNativePermit;\\\\n    private HeptaAccessibilityService.FlightNativeCheck flightNativeCheck;\\\\n    private final java.util.concurrent.atomic.AtomicBoolean flightNativeEntered=new java.util.concurrent.atomic.AtomicBoolean();\\\\n    private final java.util.Set<String> flightNativeAttemptedRuns=new java.util.HashSet<String>();\\\\n    private Journal journal;\\\\n    /** Shopping-only type endpoints. These fixtures cannot create an ARM or native token. */\\\\n    private static final class Journal{\\\\n        String bindingSha;\\\\n        private Journal(){throw new UnsupportedOperationException(\\\\\\\"query-only journal type\\\\\\\");}\\\\n    }\\\\n    private static final class ShoppingDispatch{\\\\n        WebRegionNativeBridge bridge;\\\\n        String run,actionKey,armRaw;\\\\n        java.util.concurrent.atomic.AtomicBoolean entered;\\\\n        long enteredAt,expiresAt;\\\\n        HeptaAccessibilityService.NativeRegionCheck liveNative;\\\\n        private ShoppingDispatch(){throw new UnsupportedOperationException(\\\\\\\"query-only shopping type\\\\\\\");}\\\\n    }\\\\n    private ShoppingDispatch requireShoppingDispatch(ActionDecision action,String run){\\\\n        throw new UnsupportedOperationException(\\\\\\\"shopping dispatch is outside this flight gate\\\\\\\");\\\\n    }\\\\n    private String dispatchSourceRun,dispatchSourceAction,dispatchCheckedRun,dispatchCheckedAction;\\\\n    private long dispatchCheckedAt;\\\\n    private boolean retired,failRecord;\\\\n    private WebFlightProgress flightProgress;\\\\n    private final java.util.concurrent.atomic.AtomicBoolean nativeQueryEntered=new java.util.concurrent.atomic.AtomicBoolean();\\\\n    private WebShoppingDomain.Navigation shoppingNavigation;\\\\n    private PendingNavigation pendingNavigation;\\\\n    private static final class SystemClock {static long elapsedRealtime(){return 1120;}}\\\\n    private static final class HeptaAccessibilityService {\\\\n        private static final class FlightNativeCheck {\\\\n            long checkedAt;\\\\n            private FlightNativeCheck(){throw new UnsupportedOperationException(\\\\\\\"native Flight token cannot be constructed in this query gate\\\\\\\");}\\\\n            boolean matches(PhoneObservation frame,WebFlightNativeStability.Permit permit){\\\\n                throw new UnsupportedOperationException(\\\\\\\"native Flight check is outside this query-only projection\\\\\\\");\\\\n            }\\\\n        }\\\\n        private static final class NativeRegionCheck{\\\\n            long checkedAt;\\\\n            private NativeRegionCheck(){throw new UnsupportedOperationException(\\\\\\\"native token cannot be constructed in this gate\\\\\\\");}\\\\n            boolean matches(PhoneObservation frame,WebRegionNativeBridge bridge){\\\\n                throw new UnsupportedOperationException(\\\\\\\"native check is outside this flight gate\\\\\\\");\\\\n            }\\\\n            JSONObject evidence()throws Exception{\\\\n                throw new UnsupportedOperationException(\\\\\\\"native evidence is outside this flight gate\\\\\\\");\\\\n            }\\\\n        }\\\\n        static final class ActionOutcome{\\\\n            final boolean accepted,dispatched,stale;\\\\n            ActionOutcome(boolean a,boolean d,boolean s){accepted=a;dispatched=d;stale=s;}\\\\n        }\\\\n    }\\\\n    private void record(String name,JSONObject evidence)throws Exception{\\\\n        if(failRecord)throw new java.io.IOException(\\\\\\\"synthetic evidence writer failure\\\\\\\");\\\\n        if(name==null||evidence==null)throw new AssertionError(\\\\\\\"record arguments\\\\\\\");\\\\n    }\\\\n    private static void need(boolean yes,String reason){WebEvidenceJson.need(yes,reason);}\\\\n    /* EXACT_METHODS */\\\\n    private interface Work{void run()throws Exception;}\\\\n    private static void rejects(Work body)throws Exception{\\\\n        boolean refused=false;try{body.run();}catch(IllegalArgumentException|IllegalStateException|java.io.IOException expected){refused=true;}\\\\n        if(!refused)throw new AssertionError(\\\\\\\"actual production dispatch method accepted a duplicate or missing source\\\\\\\");\\\\n    }\\\\n    static boolean verify(WebTaskDomain d,WebFlightProgress p,ActionDecision action,String run,int scenario)throws Exception{\\\\n        WebFlightDispatchProjection f=new WebFlightDispatchProjection();\\\\n        f.domain=d;f.dispatchSource=d;f.dispatchSourceRun=run;f.dispatchSourceAction=actionKey(action);\\\\n        f.purpose=WebTaskPurpose.fromOwner(d.flight.goal.immutableOwner);f.taskId=d.taskId;\\\\n        need(f.purpose.flight!=null,\\\\\\\"the retained query scenarios require the actual flight purpose\\\\\\\");\\\\n        f.dispatchCheckedRun=run;f.dispatchCheckedAction=actionKey(action);f.dispatchCheckedAt=1111;\\\\n        f.flightProgress=p.reserveQuery(d.flight,action,run);\\\\n        if(scenario==0){\\\\n            // The service deliberately rechecks authorization twice before its one platform call.\\\\n            f.requireDispatch(action,run);f.requireDispatch(action,run);\\\\n            f.beforeNativeClickInvocation(action,run);\\\\n            rejects(()->f.beforeNativeClickInvocation(action,run));\\\\n        }else if(scenario==1||scenario==2){\\\\n            f.requireDispatch(action,run);f.beforeNativeClickInvocation(action,run);\\\\n            f.modelActionOutcome(action,run,new HeptaAccessibilityService.ActionOutcome(scenario==1,scenario==1,false),1112,1115);\\\\n            rejects(()->f.requireDispatch(action,run));\\\\n            rejects(()->f.beforeNativeClickInvocation(action,run));\\\\n            if(f.dispatchSource!=null||f.dispatchCheckedRun!=null||f.dispatchCheckedAction!=null||f.dispatchCheckedAt!=0)\\\\n                throw new AssertionError(\\\\\\\"original outcome must retire the dispatch capability even when false\\\\\\\");\\\\n        }else if(scenario==3){\\\\n            f.beforeNativeClickInvocation(action,run);f.failRecord=true;\\\\n            rejects(()->f.modelActionOutcome(action,run,new HeptaAccessibilityService.ActionOutcome(true,true,false),1112,1115));\\\\n            rejects(()->f.requireDispatch(action,run));rejects(()->f.beforeNativeClickInvocation(action,run));\\\\n        }else if(scenario==4){\\\\n            f.beforeNativeClickInvocation(action,run);\\\\n            rejects(()->f.modelActionOutcome(action,\\\\\\\"00000000000000000000000000000000\\\\\\\",\\\\n                    new HeptaAccessibilityService.ActionOutcome(true,true,false),1112,1115));\\\\n            rejects(()->f.requireDispatch(action,run));rejects(()->f.beforeNativeClickInvocation(action,run));\\\\n        }else if(scenario==5){\\\\n            f.dispatchSource=null;\\\\n            rejects(()->f.beforeNativeClickInvocation(action,run));\\\\n        }else if(scenario==6){\\\\n            f.dispatchSourceAction=\\\\\\\"click\\\\\\\\nforeign\\\\\\\";\\\\n            rejects(()->f.beforeNativeClickInvocation(action,run));\\\\n            if(f.nativeQueryEntered.get())throw new AssertionError(\\\\\\\"wrong action consumed platform gate\\\\\\\");\\\\n        }else if(scenario==7){\\\\n            f.dispatchCheckedRun=null;f.dispatchCheckedAction=null;f.dispatchCheckedAt=0;\\\\n            rejects(()->f.requireDispatch(action,run));\\\\n        }else throw new AssertionError(\\\\\\\"unknown projection case\\\\\\\");\\\\n        return true;\\\\n    }\\\\n}\\\\n\\\"\",\"count\":1},{\"before\":\"METHOD_PINS=json.loads(\\\"[{\\\\\\\"signature\\\\\\\":\\\\\\\"void requireDispatch(ActionDecision action,String run)\\\\\\\",\\\\\\\"bytes\\\\\\\":489,\\\\\\\"sha256\\\\\\\":\\\\\\\"3f9127fe713d07ceeaa8fa3df67c43f511d8971c522cb509436c611cc01928fe\\\\\\\"},{\\\\\\\"signature\\\\\\\":\\\\\\\"void beforeNativeClickInvocation(ActionDecision action,String run)\\\\\\\",\\\\\\\"bytes\\\\\\\":1510,\\\\\\\"sha256\\\\\\\":\\\\\\\"14d83f54219030feedda546671d02b9185445f8777cf63ce471ce4e6f597ef3b\\\\\\\"},{\\\\\\\"signature\\\\\\\":\\\\\\\"private static String actionKey(ActionDecision action)\\\\\\\",\\\\\\\"bytes\\\\\\\":121,\\\\\\\"sha256\\\\\\\":\\\\\\\"499761ddb3a83b19dbd05739065599f2d8247cf122545fef77fb9ddeff16093f\\\\\\\"},{\\\\\\\"signature\\\\\\\":\\\\\\\"void modelActionOutcome(ActionDecision action,String run,HeptaAccessibilityService.ActionOutcome outcome,\\\\\\\",\\\\\\\"bytes\\\\\\\":3775,\\\\\\\"sha256\\\\\\\":\\\\\\\"44b373cc7c4d038b3381abda5096696e0204f345aba3cf33d912e7ee022dcfd0\\\\\\\"},{\\\\\\\"signature\\\\\\\":\\\\\\\"private static final class PendingNavigation\\\\\\\",\\\\\\\"bytes\\\\\\\":596,\\\\\\\"sha256\\\\\\\":\\\\\\\"f4ad2a361ac83bd5f1f38ca3bcf4ef7057eb5d73aa5db5e8f4684631c27c3be0\\\\\\\"}]\\\")\",\"after\":\"METHOD_PINS=json.loads(\\\"[{\\\\\\\"signature\\\\\\\":\\\\\\\"void requireDispatch(ActionDecision action,String run)\\\\\\\",\\\\\\\"bytes\\\\\\\":489,\\\\\\\"sha256\\\\\\\":\\\\\\\"3f9127fe713d07ceeaa8fa3df67c43f511d8971c522cb509436c611cc01928fe\\\\\\\"},{\\\\\\\"signature\\\\\\\":\\\\\\\"void beforeNativeClickInvocation(ActionDecision action,String run)\\\\\\\",\\\\\\\"bytes\\\\\\\":2129,\\\\\\\"sha256\\\\\\\":\\\\\\\"8b4189993718c610916a1fd15a5b06390a90168f7db4ff8348563c8c28ca239b\\\\\\\"},{\\\\\\\"signature\\\\\\\":\\\\\\\"private static String actionKey(ActionDecision action)\\\\\\\",\\\\\\\"bytes\\\\\\\":121,\\\\\\\"sha256\\\\\\\":\\\\\\\"499761ddb3a83b19dbd05739065599f2d8247cf122545fef77fb9ddeff16093f\\\\\\\"},{\\\\\\\"signature\\\\\\\":\\\\\\\"void modelActionOutcome(ActionDecision action,String run,HeptaAccessibilityService.ActionOutcome outcome,\\\\\\\",\\\\\\\"bytes\\\\\\\":3835,\\\\\\\"sha256\\\\\\\":\\\\\\\"8d0ae19b4415d856384728ae52e7151a6a0f90ec0c58d0f4ab73c1c16bb837c9\\\\\\\"},{\\\\\\\"signature\\\\\\\":\\\\\\\"private static final class PendingNavigation\\\\\\\",\\\\\\\"bytes\\\\\\\":596,\\\\\\\"sha256\\\\\\\":\\\\\\\"f4ad2a361ac83bd5f1f38ca3bcf4ef7057eb5d73aa5db5e8f4684631c27c3be0\\\\\\\"}]\\\")\",\"count\":1}]}],\"exact_changed_paths\":[\"AndroidManifest.xml\",\"src/org/trillionnium/hepta/local/HeptaAccessibilityService.java\",\"src/org/trillionnium/hepta/local/LocalTaskController.java\",\"src/org/trillionnium/hepta/local/TaskCompletionGate.java\",\"src/org/trillionnium/hepta/local/WebFlightNativeStability.java\",\"src/org/trillionnium/hepta/local/WebFlightSession.java\",\"src/org/trillionnium/hepta/local/WebShoppingDomain.java\",\"tests/completion/TaskCompletionGateHostTest.java\",\"tests/qualification-scope/BackgroundObservationFixture.template\",\"tests/qualification-scope/ServiceFixture.template\",\"tests/qualification-scope/fixtures/org/trillionnium/hepta/local/WebFlightSession.java\",\"tests/qualification-scope/prepare_fixture.py\",\"tests/warm-finalization/prepare_fixture.py\",\"tests/web-flight/run_query_host_tests.py\"],\"source_inventory_bytes\":103795,\"query_java_source_count\":50,\"predecessor_release\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-main-sign-r1/RESULT.json\",\"bytes\":31662,\"sha256\":\"3caa0d8ae5252352fb606db1d851fd9e960423c0f7374a76c58b89c688556535\"},\"predecessor_release_source_commit\":\"dd2cd48054c2c6f0b2597b7d9be05edd8ce6b34e\",\"predecessor_apk\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-main-sign-r1/out/hepta-local-0.55.0.apk\",\"bytes\":21014354,\"sha256\":\"ea485e6d28544d75a9010e441aae8df348d1b64884f9ff7a50cb909a3f8ea45e\"},\"version_code\":56,\"version_name\":\"0.56.0-flight-stability\",\"candidate_scope\":\"actual source successor for bounded native Flight-home stability and immutable terminal completion; Flight result provider remains false\",\"query_case_expectation\":{\"cases\":40,\"assertions\":187,\"case_names\":[\"literal_city_data_is_not_a_verified_route\",\"matching_form_without_model_actions_cannot_query\",\"real_class_selection_chain_enables_exact_query_once\",\"accepted_picker_click_waits_for_native_form_readback\",\"false_city_outcome_never_confirms\",\"stale_city_outcome_never_confirms\",\"date_before_two_city_confirmations_withheld\",\"wrong_after_city_literal_stays_pending\",\"dom_city_without_same_native_value_stays_pending\",\"foreign_native_city_descendant_rejected\",\"two_cities_without_full_calendar_date_cannot_query\",\"wrong_after_month_day_stays_pending\",\"wrong_after_weekday_stays_pending\",\"date_before_dispatch_end_cannot_confirm\",\"later_route_change_invalidates_current_query\",\"later_date_change_invalidates_year_confirmation\",\"native_field_disappears_query_withheld\",\"two_adults_are_not_one_adult_query\",\"disabled_dom_query_cannot_mint_target\",\"duplicate_native_query_even_disabled_refuses\",\"another_binding_cannot_import_selection_chain\",\"navigation_epoch_regression_cannot_import_progress\",\"query_reservation_is_not_a_dispatch\",\"second_query_reservation_refused\",\"actual_query_outcome_and_after_capture_remain_not_results\",\"false_query_outcome_consumes_attempt\",\"accepted_query_without_platform_entry_refused\",\"query_outcome_before_capture_refused\",\"query_outcome_wrong_model_run_refused\",\"query_outcome_twice_refused\",\"unknown_booking_body_is_read_only_pending\",\"city_airport_combination_not_silently_normalized\",\"actual_session_dispatch_methods_0\",\"actual_session_dispatch_methods_1\",\"actual_session_dispatch_methods_2\",\"actual_session_dispatch_methods_3\",\"actual_session_dispatch_methods_4\",\"actual_session_dispatch_methods_5\",\"actual_session_dispatch_methods_6\",\"actual_session_dispatch_methods_7\"]},\"query_runner_original\":{\"bytes\":41005,\"sha256\":\"0f4d983138ed8bcf5f0b622ee4d4063048e83413eafe3586595521f5e1b7eb45\"},\"query_runner_count_adapter\":{\"before\":\"    need(len(PURE_PATHS)==45 and len(generated_factories)==3,\\\"fixed 43 production plus 2 retained plus 3 factory inputs\\\")\",\"after\":\"    need(len(PURE_PATHS)==46 and len(generated_factories)==3,\\\"fixed 44 production plus 2 retained plus 3 factory inputs\\\")\",\"count\":1}}")

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
        old_raw = checked(prior_source[name], delta["base"], "original signed55 source")
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
        need(current.encode("utf-8","strict") == old_raw, "exact inverse signed55 source restoration")

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
    path=OUT/"hepta-local-0.56.0-unsigned.apk"
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
    path=ROOT/"query40-runner.py"
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
            "runner_original_sha256":sha(query_runner_original_raw),
            "runner_count_adapter":CONFIG["query_runner_count_adapter"],
            "runner_corrected_outside_source_tree":True,"repository_runner_count_guard_known_incompatible":True,
            "executed_in_process":True,"owned_child_groups_managed_by_original_runner":True}


# Pending future source pins reject before any filesystem claim or child.
case_expectation(CONFIG["query_case_expectation"],"query successor")
for name in ("aggregate","decoded_input","compiler_inputs","query_runner","query_runner_original"):
    value = CONFIG[name]
    need(type(value) is dict and type(value.get("bytes")) is int and value["bytes"] > 0
         and type(value.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}",value["sha256"]),
         "sealed main56 candidate artifact required: "+name)
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
need(type(CONFIG["focused_result"]) is dict and type(CONFIG["focused_result"].get("bytes")) is int
     and re.fullmatch(r"[0-9a-f]{64}", CONFIG["focused_result"].get("sha256", "")),
     "actual Pocket4 focused39 RESULT pins required")
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
need(original_data["schema"] == "hepta.main55-pocket4-java-android-input.v1",
     "actual completed55 full input is the immutable predecessor")
shared_aggregate_raw = load_bound(PRIOR_BUILD/"AGGREGATE.json", CONFIG["original_aggregate"], original_facts)
need(blob(shared_aggregate_raw) == CONFIG["original_aggregate"]["git"]
     and original_data["aggregate_raw_utf8"].encode("utf-8","strict") == shared_aggregate_raw,
     "actual signed55 aggregate and original full input agree")
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
data["schema"] = "hepta.main56-pocket4-java-android-input.v1"
data["aggregate_raw_utf8"] = materialized_aggregate_raw.decode("utf-8","strict")
data["expected_compiler_inputs"] = materialized_compiler
checked(encoded(original_data["expected_compiler_inputs"]), CONFIG["prior_compiler_inputs"], "actual55 compiler map")
checked(encoded(materialized_compiler), CONFIG["compiler_inputs"], "sealed successor compiler map")
old_compiler = {row["path"]:row["sha256"] for row in original_data["expected_compiler_inputs"]}
new_compiler = {row["path"]:row["sha256"] for row in materialized_compiler}
need(set(old_compiler).issubset(new_compiler), "no original compiler input removed")
compiler_changed_paths = sorted(name for name in new_compiler
                                if name not in old_compiler or new_compiler[name] != old_compiler[name])
need(compiler_changed_paths
     and set(compiler_changed_paths).issubset(CONFIG["exact_changed_paths"]),
     "all changed or added compiler members are explicitly reviewed source deltas")
input_raw = checked(encoded(data), CONFIG["decoded_input"], "complete successor build input from actual55 bytes")
data = strict(input_raw)
need(data["schema"] == "hepta.main56-pocket4-java-android-input.v1"
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
need(prior_build["schema"] == "hepta.main55-pocket4-java-native-reuse-stage.v1"
     and prior_build["root"] == str(PRIOR_BUILD)
     and prior_build["all_pass"] is True and type(prior_build["exit_code"]) is int
     and prior_build["exit_code"] == 0 and prior_build["originals_unchanged"] is True
     and prior_build["written_files_unchanged"] is True and prior_build["current_source_unchanged"] is True
     and prior_build["android_java_compiled_here"] is True and prior_build["native_recompiled_here"] is False
     and prior_build["native_payloads_reused_from_signed54"] is True
     and prior_build["signed"] is False and prior_build["published"] is False
     and prior_build["phone_actions"] == 0 and prior_build["business_verified"] is False,
     "the original signed55 Android2 build is preserved as its actual successful result")
need(prior_build["source_candidate_git"] == CONFIG["original_aggregate"]["git"]
     and prior_build["source_inventory_sha256"] == CONFIG["original_source_inventory_sha256"]
     and prior_build["source_inputs"] == original_data["expected_compiler_inputs"]
     and prior_build["stage_sha256"] == CONFIG["prior_build_stage"]["sha256"]
     and prior_build["input_sha256"] == CONFIG["original_decoded_input"]["sha256"],
     "original signed55 Android2 result remains bound to its own source")
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
     "original signed55 Android2 stage and exact inputs")
prior_source, prior_source_facts = snapshot(PRIOR_BUILD/"source")
validate_map(prior_source, strict(shared_aggregate_raw)["inventory"]["files"], True)
need(sha(encoded(rows(prior_source))) == CONFIG["original_source_inventory_sha256"],
     "original complete594 source identity")
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
need(release["schema"] == "hepta.isolated-v55-assembly.v1" and release["all_pass"] is True
     and type(release["exit_code"]) is int and release["exit_code"] == 0
     and release["version_code"] == 55
     and release["source_commit"] == CONFIG["predecessor_release_source_commit"]
     and release["source_inventory_sha256"] == CONFIG["original_source_inventory_sha256"]
     and release["pocket4_build_result_sha256"] == CONFIG["prior_build_result"]["sha256"]
     and release["compiled_and_published_source_byte_identical"] is True
     and release["source_files_unchanged"] is True
     and release["apk_sha256"] == CONFIG["predecessor_apk"]["sha256"]
     and release["apk_bytes"] == CONFIG["predecessor_apk"]["bytes"]
     and release["signer_certificate_sha256"] == "202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5"
     and release["library_pins"] == CONFIG["native_pins"],
     "actual signed55 release, exact Android2 input and native predecessor")
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
     "explicit current main56 source identity")
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
need(focused["schema"] == "hepta.main56-wire4-focused-host-stage.v1"
     and focused["all_pass"] is True and focused["java_sources"] == 51
     and focused["pure_production_sources"] == 44 and focused["exact_method_projection_count"] == 15
     and focused["current_source_tree_unchanged"] is True
     and focused["prior_successful_run_preserved"] is True
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
query_runner_original_raw=checked(target["tests/web-flight/run_query_host_tests.py"],
    CONFIG["query_runner_original"],"unchanged repository query runner")
query_adapter=CONFIG["query_runner_count_adapter"]
need(type(query_adapter) is dict and set(query_adapter)=={"before","after","count"}
     and type(query_adapter["count"]) is int and query_adapter["count"]==1
     and type(query_adapter["before"]) is str and type(query_adapter["after"]) is str,
     "one sealed external count-only query runner adaptation")
query_before=query_adapter["before"].encode("utf-8");query_after=query_adapter["after"].encode("utf-8")
need(query_before and query_after and query_runner_original_raw.count(query_before)==1,
     "one exact original query admission count")
query_runner_raw=checked(query_runner_original_raw.replace(query_before,query_after,1),
    CONFIG["query_runner"],"exact external corrected query runner")
need(query_runner_raw.count(query_after)==1
     and query_runner_raw.replace(query_after,query_before,1)==query_runner_original_raw,
     "external runner reverses to the full unchanged repository original")
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
result = {"schema":"hepta.main56-pocket4-java-native-reuse-stage.v1","root":str(ROOT),
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
          "original_full_input_reconstructed":False,"original_full_input_reused_from_signed55_build":True,
          "sdk_dependency_result":CONFIG["sdk_download_result"],
          "revision":"sealed-source-successor-from-actual-signed55-r1",
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
    written.append(write_new(ROOT/"query40-runner.py",query_runner_raw))
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
        need(prior_artifact_paths(PRIOR_BUILD) == list(prior_tree_facts), "original signed55 Android2 file membership unchanged")
        prior_source_after, prior_source_after_facts = snapshot(PRIOR_BUILD/"source")
        need(prior_source_after == prior_source and prior_source_after_facts == prior_source_facts,
             "original signed55 Android2 source bytes and identities unchanged")
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
    summary={"schema":"hepta.main56-pocket4-java-native-reuse-summary.v1","root":str(ROOT),
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
