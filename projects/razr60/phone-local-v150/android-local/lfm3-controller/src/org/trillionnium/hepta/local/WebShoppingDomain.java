package org.trillionnium.hepta.local;

import org.json.JSONObject;
import org.trillionnium.hepta.local.web.WebShoppingGoal;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebSitePolicy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A same-frame official-shopping capability restriction. It does not dispatch.
 * Targets are real native AX IDs with the actual card text/ancestry/geometry bridge.
 * Full before/after raw hashes bind ARM; stable region semantics bind the model action page key.
 * Source/currency/price data never originate in a model answer or search snippet.
 */
final class WebShoppingDomain {
    static final String SCHEMA="hepta.mi-current-action-domain.v2";
    final String taskId,ownerSha,contractSha,authorizationSha,observationId,stateSha,generation,bindingSha;
    final String instance,url,phase,pageKey;
    final int displayId,windowId;
    final long epoch,captureStarted,captureEnded;
    final Set<String> clickIds;
    private final Map<String,MiPublicProductPage.Link> links;
    private final Map<String,Object> proof;
    private final MiPublicProductPage page;
    private final boolean localPriceVerified;
    private final Navigation navigation;
    private final String sourceCaptureRaw,observedArmRaw;
    private final WebRegionNativeBridge regionBridge;

    private WebShoppingDomain(String task,WebShoppingGoal goal,TaskAuthorization.Gate auth,PhoneObservation frame,
            WebEvidenceReceipt receipt,String binding,String phase,String key,
            Map<String,MiPublicProductPage.Link> links,MiPublicProductPage page,boolean priceVerified,
            Navigation navigation,Map<String,Object> proof,String sourceCaptureRaw,WebRegionNativeBridge regionBridge){
        taskId=task;ownerSha=goal.ownerSha256;contractSha=goal.contractSha256;authorizationSha=auth.authorization.sha256;
        observationId=frame.id;stateSha=frame.treeSha256;generation=frame.backgroundGeneration;bindingSha=binding;
        instance=receipt.instance;url=receipt.url;epoch=receipt.epoch;displayId=receipt.displayId;windowId=receipt.windowId;
        captureStarted=receipt.started;captureEnded=receipt.ended;this.phase=phase;pageKey=key;
        this.links=Collections.unmodifiableMap(new LinkedHashMap<String,MiPublicProductPage.Link>(links));
        clickIds=Collections.unmodifiableSet(new HashSet<String>(links.keySet()));this.page=page;
        localPriceVerified=priceVerified;this.navigation=navigation;this.sourceCaptureRaw=sourceCaptureRaw;
        this.regionBridge=regionBridge;this.observedArmRaw=null;
        this.proof=Collections.unmodifiableMap(new LinkedHashMap<String,Object>(proof));
    }
    private WebShoppingDomain(WebShoppingDomain original,Navigation navigation){
        this(original,navigation,original.observedArmRaw);
    }
    private WebShoppingDomain(WebShoppingDomain original,Navigation navigation,String armRaw){
        taskId=original.taskId;ownerSha=original.ownerSha;contractSha=original.contractSha;authorizationSha=original.authorizationSha;
        observationId=original.observationId;stateSha=original.stateSha;generation=original.generation;bindingSha=original.bindingSha;
        instance=original.instance;url=original.url;epoch=original.epoch;displayId=original.displayId;windowId=original.windowId;
        captureStarted=original.captureStarted;captureEnded=original.captureEnded;phase=original.phase;pageKey=original.pageKey;
        links=original.links;clickIds=original.clickIds;page=original.page;localPriceVerified=original.localPriceVerified;
        sourceCaptureRaw=original.sourceCaptureRaw;regionBridge=original.regionBridge;observedArmRaw=armRaw;
        this.navigation=navigation;Map<String,Object> out=new LinkedHashMap<String,Object>(original.proof);
        if(navigation!=null){
            out.put("model_navigation",navigation.evidence());out.put("model_navigation_confirmed",true);
            out.put("result_ready_for_completion_gate",localPriceVerified);
        }
        if(armRaw!=null){out.put("observed_link_arm_json_utf8",armRaw);out.put("observed_link_armed",true);}
        proof=Collections.unmodifiableMap(out);
    }
    static WebShoppingDomain observed(String task,WebShoppingGoal goal,TaskAuthorization.Gate auth,PhoneObservation frame,
                                      WebEvidenceReceipt receipt,JSONObject immutableBinding)throws Exception{
        String binding=common(task,goal,auth,frame,receipt,immutableBinding);
        need("captured".equals(receipt.status),"actual captured page required");
        JSONObject dom=receipt.dom(),capture=receipt.capture();WebSitePolicy policy=WebSitePolicy.forShopping(goal);
        MiPublicProductPage page=MiPublicProductPage.read(goal,policy,receipt.url,dom);
        WebNativeGeometry geometry=WebNativeGeometry.read(capture,dom,receipt.displayId,receipt.windowId,receipt.stability());
        WebRegionNativeBridge nativeBridge=null;
        Map<String,MiPublicProductPage.Link> targets=new LinkedHashMap<String,MiPublicProductPage.Link>();
        List<Map<String,Object>> capabilities=new ArrayList<Map<String,Object>>();
        Map<String,Object> proof=base(task,goal,auth,frame,receipt,binding);
        proof.put("page",page.evidence());proof.put("site_policy",jsonMap(policy.evidence()));
        proof.put("site_policy_sha256",policy.sha256);proof.put("native_geometry",geometry==null?null:geometry.evidence());
        if(geometry!=null&&!page.modalPresent&&page.productLinks.size()==1
                &&"official_public_search".equals(page.phase)){
            MiPublicProductPage.Link link=page.productLinks.get(0);
            nativeBridge=WebRegionNativeBridge.bind(frame,receipt);
            if(nativeBridge!=null&&receipt.stability()!=null&&receipt.stability().region!=null
                    &&nativeBridge.anchorDomPath.equals(link.path)
                    &&nativeBridge.regionRoot.equals(receipt.stability().region.rootPath)
                    &&receipt.stability().permitsActionTargetPath(link.path)){
                PhoneObservation.Node node=nativeBridge.anchor;
                targets.put(node.id,link);Map<String,Object> cap=nodeEvidence(node);
                cap.put("purpose","open_observed_official_product_detail");cap.put("observed_link",link.evidence());
                cap.put("target_source","same_frame_native_accessibility_node_id");
                cap.put("native_region_bridge",jsonMap(nativeBridge.evidence()));
                cap.put("css_rect_used_as_target",false);capabilities.add(cap);
            }else nativeBridge=null;
        }
        boolean localPrice=false;
        Map<String,Object> visible=new LinkedHashMap<String,Object>();
        if(geometry!=null&&!page.modalPresent&&page.detail!=null&&page.detail.exactPublicPrice
                &&!goal.singleUnitRequested&&!goal.specificationsRequested){
            MiPublicProductPage.Detail detail=page.detail;
            PhoneObservation.Node model=uniqueReadable(frame,geometry,detail.modelLabel);
            PhoneObservation.Node amount=uniqueReadable(frame,geometry,detail.priceRaw);
            PhoneObservation.Node currency=uniqueReadable(frame,geometry,detail.currencyRaw);
            if(model!=null&&amount!=null&&currency!=null&&model!=amount&&model!=currency&&amount!=currency){
                localPrice=true;visible.put("model",nodeEvidence(model));visible.put("price",nodeEvidence(amount));
                visible.put("currency",nodeEvidence(currency));
            }
        }
        proof.put("phase",page.phase);proof.put("native_ax_capabilities",capabilities);
        proof.put("allowed_click_ids",new ArrayList<String>(targets.keySet()));
        proof.put("actual_product_native_readback",visible);proof.put("same_frame_public_price_observed",localPrice);
        proof.put("model_navigation_confirmed",false);proof.put("model_navigation",null);
        proof.put("observed_link_armed",false);proof.put("observed_link_arm_json_utf8",null);
        proof.put("result_ready_for_completion_gate",false);
        proof.put("missing",new ArrayList<String>(page.missing));
        proof.put("next_goal",!targets.isEmpty()?"打开同帧实际 AX3000T 官方商品链接；不要点击购买、登录、领券或购物车。":
                localPrice?"已观察到商品公开价；仍须同任务原生模型导航因果链及最终清理门。":
                "当前页面缺少可验证的公开商品控件或价格；只能等待或报告未完成，不能猜测SKU、价格、币种。");
        JSONObject semantic=new JSONObject().put("native_url",receipt.url).put("instance",receipt.instance)
                .put("epoch",receipt.epoch).put("policy_sha256",policy.sha256)
                .put("native_geometry_sha256",geometry==null?JSONObject.NULL:geometry.fingerprint)
                .put("allowed_click_ids",new org.json.JSONArray(targets.keySet()))
                .put("native_region_semantic_sha256",nativeBridge==null?JSONObject.NULL:nativeBridge.semanticFingerprint)
                .put("selected_region_sha256",receipt.stability()==null||receipt.stability().region==null?JSONObject.NULL:receipt.stability().region.fullRegionSha256)
                .put("selected_region_ancestor_sha256",receipt.stability()==null||receipt.stability().region==null?JSONObject.NULL:receipt.stability().region.ancestorSha256)
                .put("page",new JSONObject(page.evidence()));
        return new WebShoppingDomain(task,goal,auth,frame,receipt,binding,page.phase,WebEvidenceJson.sha(semantic.toString()),
                targets,page,localPrice,null,proof,capture.toString(),nativeBridge);
    }
    static WebShoppingDomain waiting(String task,WebShoppingGoal goal,TaskAuthorization.Gate auth,PhoneObservation frame,
                                    WebEvidenceReceipt receipt,JSONObject immutableBinding)throws Exception{
        String binding=common(task,goal,auth,frame,receipt,immutableBinding);
        need(("unavailable".equals(receipt.status)||"state_changed".equals(receipt.status))&&!receipt.cleanupKnown,
                "only authenticated metadata-only capture wait");
        Map<String,Object> proof=base(task,goal,auth,frame,receipt,binding);proof.put("phase","official_page_capture_pending");
        proof.put("capture_callback",jsonMap(receipt.callback()));proof.put("allowed_click_ids",Collections.emptyList());
        proof.put("native_ax_capabilities",Collections.emptyList());proof.put("same_frame_public_price_observed",false);
        proof.put("model_navigation_confirmed",false);proof.put("result_ready_for_completion_gate",false);
        proof.put("next_goal","网页原始证据尚未稳定；只能等待或报告未完成。");
        return new WebShoppingDomain(task,goal,auth,frame,receipt,binding,"official_page_capture_pending",
                WebEvidenceJson.sha(receipt.callback().toString()+"\n"+frame.id),
                Collections.<String,MiPublicProductPage.Link>emptyMap(),null,false,null,proof,null,null);
    }
    private static String common(String task,WebShoppingGoal goal,TaskAuthorization.Gate auth,PhoneObservation frame,
                               WebEvidenceReceipt receipt,JSONObject immutableBinding)throws Exception{
        need(goal!=null&&auth!=null&&receipt!=null&&task.equals(auth.taskId)&&goal.ownerSha256.equals(auth.authorization.instructionSha256)
                &&WebShoppingGoal.TOOL_CEILING.containsAll(auth.authorization.allowedTools),"same original bounded shopping authorization");
        need(WebEvidenceProtocol.HELPER_VERSION_CODE==6
                &&"hepta.web-helper.binding.v4".equals(WebEvidenceProtocol.BINDING_SCHEMA)
                &&"org.trillionnium.hepta.webhelper.IWebEvidence.v4".equals(WebEvidenceProtocol.DESCRIPTOR),
                "shopping requires explicit code6/v4 peer and independently replayed scoped capture");
        WebSitePolicy policy=WebSitePolicy.forShopping(goal);
        need(immutableBinding!=null&&WebEvidenceProtocol.BINDING_SCHEMA.equals(immutableBinding.get("schema"))
                &&task.equals(immutableBinding.get("task_id"))&&goal.owner.equals(immutableBinding.get("owner"))
                &&goal.ownerSha256.equals(immutableBinding.get("owner_sha256"))&&goal.contractSha256.equals(immutableBinding.get("contract_sha256"))
                &&WebShoppingGoal.KIND.equals(immutableBinding.get("goal_kind"))
                &&policy.id.equals(immutableBinding.get("site_policy_id"))&&policy.sha256.equals(immutableBinding.get("site_policy_sha256"))
                &&policy.initialUrl.equals(immutableBinding.get("initial_url"))
                &&auth.authorization.sha256.equals(immutableBinding.getJSONObject("authorization").get("authorization_sha256"))
                &&WebEvidenceJson.number(immutableBinding.getJSONObject("helper_identity"),"version_code")==6,
                "exact per-lease shopping contract/site/authority binding required");
        String binding=WebEvidenceBinding.sha256(immutableBinding);
        need(frame!=null&&!frame.nodesTruncated&&WebEvidenceProtocol.HELPER_PACKAGE.equals(frame.packageName)
                &&frame.windowMetadata!=null&&"observed".equals(frame.windowMetadata.status)
                &&Integer.valueOf(1).equals(frame.windowMetadata.type)&&frame.windowMetadata.displayId!=null
                &&frame.windowMetadata.displayId==receipt.displayId&&frame.windowId==receipt.windowId
                &&receipt.displayId>0&&frame.backgroundGeneration!=null&&binding.equals(receipt.bindingSha)
                &&WebEvidenceJson.number(immutableBinding.getJSONObject("background"),"display_id")==receipt.displayId
                &&frame.backgroundGeneration.equals(immutableBinding.getJSONObject("background").get("generation")),
                "same current owned AX/DOM application window required");
        return binding;
    }
    private static Map<String,Object> base(String task,WebShoppingGoal goal,TaskAuthorization.Gate auth,PhoneObservation frame,
                                           WebEvidenceReceipt receipt,String binding){
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema",SCHEMA);out.put("task_id",task);
        out.put("owner_sha256",goal.ownerSha256);out.put("contract_sha256",goal.contractSha256);out.put("authorization_sha256",auth.authorization.sha256);
        out.put("observation_id",frame.id);out.put("observation_state_sha256",frame.treeSha256);out.put("app_tree_sha256",frame.state.appTreeSha256);
        out.put("binding_sha256",binding);out.put("webview_instance",receipt.instance);out.put("navigation_epoch",receipt.epoch);
        out.put("display_id",receipt.displayId);out.put("window_id",receipt.windowId);out.put("background_generation",frame.backgroundGeneration);
        out.put("current_native_url",receipt.url);out.put("dom_sha256",receipt.domSha);out.put("business_verified",false);
        out.put("grants_tool_authority",false);out.put("bootstrap_search_is_model_query",false);
        out.put("css_to_screen_mapping_used",false);out.put("dom_layout_visibility_is_screen_proof",false);
        out.put("final_native_and_cleanup_gates_verified",false);return out;
    }
    String observedLinkAnchorPath(ActionDecision action){
        requireCurrent(action);need("click".equals(action.action)&&links.containsKey(action.nodeId),"current product click required");
        return links.get(action.nodeId).path;
    }
    WebShoppingDomain withObservedLinkArm(JSONObject actualArm)throws Exception{
        need(observedArmRaw==null&&sourceCaptureRaw!=null&&regionBridge!=null&&clickIds.size()==1,
                "single actual fresh product region can accept one ARM");
        JSONObject source=new JSONObject(sourceCaptureRaw);
        org.trillionnium.hepta.webprotocol.WebDomStability.Result stable=
                org.trillionnium.hepta.webprotocol.WebDomStability.verify(source.getString("before_dom_raw_utf8"),
                        source.getString("dom_raw_utf8"),WebSitePolicy.ID,source.getJSONObject("dom_stability"));
        need(org.trillionnium.hepta.webprotocol.WebObservedNavigation.ARM_SCHEMA.equals(actualArm.get("schema"))
                &&taskId.equals(actualArm.get("task_id"))&&bindingSha.equals(actualArm.get("binding_sha256"))
                &&instance.equals(actualArm.get("webview_instance"))&&epoch==WebEvidenceJson.number(actualArm,"navigation_epoch")
                &&displayId==WebEvidenceJson.number(actualArm,"display_id")&&windowId==WebEvidenceJson.number(actualArm,"actual_window_id")
                &&source.get("challenge").equals(actualArm.get("source_capture_challenge"))
                &&source.get("dom_sha256").equals(actualArm.get("source_dom_sha256"))
                &&source.get("before_dom_sha256").equals(actualArm.get("source_before_dom_sha256"))
                &&source.get("dom_stability_sha256").equals(actualArm.get("source_stability_sha256"))
                &&stable.region!=null&&regionBridge.anchorDomPath.equals(actualArm.get("anchor_dom_path"))
                &&stable.region.fullRegionSha256.equals(actualArm.get("region_sha256"))
                &&stable.region.hrefResolved.equals(actualArm.get("observed_href_resolved"))
                &&Boolean.FALSE.equals(actualArm.get("native_click_observed"))
                &&Boolean.FALSE.equals(actualArm.get("navigation_dispatched"))
                &&Boolean.FALSE.equals(actualArm.get("transaction_authority"))
                &&Boolean.FALSE.equals(actualArm.get("business_verified")),
                "ARM must describe this exact last successful capture and unique native target");
        // The Client has already replayed the original request with verifyArm.
        // This setter preserves its exact typed record; it creates no request or outcome.
        return new WebShoppingDomain(this,navigation,org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(actualArm));
    }
    WebShoppingDomain withNavigation(Navigation proof){
        need(proof!=null&&proof.matches(this),"navigation belongs to another task/product/page");
        return new WebShoppingDomain(this,proof);
    }
    boolean resultReady(){return localPriceVerified&&navigation!=null&&navigation.matches(this);}
    Map<String,Object> resultRecord(){
        need(resultReady()&&page!=null&&page.detail!=null,"actual same-product result and navigation missing");
        Map<String,Object> out=new LinkedHashMap<String,Object>(page.detail.evidence());
        out.put("committed_url",url);out.put("task_id",taskId);out.put("owner_sha256",ownerSha);out.put("contract_sha256",contractSha);
        out.put("observation_id",observationId);out.put("observation_state_sha256",stateSha);out.put("binding_sha256",bindingSha);
        out.put("webview_instance",instance);out.put("navigation_epoch",epoch);out.put("display_id",displayId);out.put("window_id",windowId);
        out.put("model_navigation",navigation.evidence());out.put("same_frame_native_labels_verified",true);
        out.put("exact_configuration_verified",false);out.put("price_scope","displayed_public_product_page_price");
        out.put("business_verified",false);out.put("final_native_and_cleanup_gates_verified",false);return out;
    }
    Map<String,Object> evidence(){return new LinkedHashMap<String,Object>(proof);}
    Set<String> clicks(Set<String> original){Set<String> out=new HashSet<String>(original);out.retainAll(clickIds);return out;}
    Set<String> edits(Set<String> original){return Collections.emptySet();}
    Set<String> openPackages(Set<String> original){return Collections.emptySet();}
    <T> Map<String,T> noNodeActions(Map<String,T> original){return Collections.emptyMap();}
    Set<String> toolMask(Set<String> original){
        Set<String> out=new HashSet<String>(Arrays.asList("wait","done"));if(!clickIds.isEmpty())out.add("click");
        if(original!=null)out.retainAll(original);return out;
    }
    void requireCurrent(ActionDecision action){
        need(action!=null&&observationId.equals(action.observationId)&&WebEvidenceProtocol.HELPER_PACKAGE.equals(action.packageName),
                "shopping action belongs to another current frame");
        if("wait".equals(action.action))return;
        if("done".equals(action.action)){need(!"success".equals(action.status)||resultReady(),"actual product result not yet independently ready");return;}
        if("click".equals(action.action)){need(action.nodeId!=null&&clickIds.contains(action.nodeId),"only current exact official product link is allowed");return;}
        throw new IllegalArgumentException("该商品页面没有已证明的只读操作；禁止购物、输入、提交或跨站操作");
    }
    static final class Navigation {
        private final String task,owner,contract,authorization,binding,generation,instance,url,run,beforeObservation,afterObservation;
        private final int display,window;private final long targetEpoch,dispatchBefore,dispatchAfter;
        private final Map<String,Object> evidence;
        private Navigation(WebShoppingDomain before,WebShoppingDomain after,String modelRun,long start,long end,ActionDecision action,Map<String,Object> helperNavigation){
            task=before.taskId;owner=before.ownerSha;contract=before.contractSha;authorization=before.authorizationSha;
            binding=before.bindingSha;generation=before.generation;instance=before.instance;url=after.url;
            display=before.displayId;window=before.windowId;targetEpoch=after.epoch;run=modelRun;
            beforeObservation=before.observationId;afterObservation=after.observationId;dispatchBefore=start;dispatchAfter=end;
            Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema","hepta.mi-model-navigation.v1");
            out.put("task_id",task);out.put("owner_sha256",owner);out.put("contract_sha256",contract);out.put("authorization_sha256",authorization);
            out.put("binding_sha256",binding);out.put("background_generation",generation);out.put("webview_instance",instance);
            out.put("display_id",display);out.put("window_id",window);out.put("model_run_id",run);out.put("action","click");out.put("node_id",action.nodeId);
            out.put("before_observation_id",beforeObservation);out.put("after_observation_id",afterObservation);
            out.put("source_url",before.url);out.put("target_url",url);out.put("source_epoch",before.epoch);out.put("target_epoch",targetEpoch);
            out.put("dispatch_before_elapsed_ms",start);out.put("dispatch_after_elapsed_ms",end);
            out.put("actual_source_link",before.links.get(action.nodeId).evidence());out.put("accepted",true);out.put("dispatched",true);out.put("stale",false);
            out.put("model_issued",true);out.put("observed_link_arm_json_utf8",before.observedArmRaw);
            out.put("helper_navigation_verdict",helperNavigation);out.put("business_verified",false);evidence=Collections.unmodifiableMap(out);
        }
        /**
         * Called only from the real controller's accepted native-model action +
         * actual executor Outcome. The clocks bracket that original dispatch.
         * Planned/unknown/stale clicks and operator navigation cannot mint this object.
         */
        static Navigation confirm(WebShoppingDomain before,WebShoppingDomain after,ActionDecision action,String nativeModelRunId,
                                  boolean accepted,boolean dispatched,boolean stale,long dispatchBefore,long dispatchAfter){
            need(before!=null&&after!=null&&action!=null&&accepted&&dispatched&&!stale
                    &&nativeModelRunId!=null&&nativeModelRunId.matches("[0-9a-f]{32}"),"actual accepted model dispatch required");
            before.requireCurrent(action);need("click".equals(action.action)&&before.links.containsKey(action.nodeId),"real product link click required");
            need("official_public_search".equals(before.phase)&&"official_product_detail".equals(after.phase)
                    &&before.taskId.equals(after.taskId)&&before.ownerSha.equals(after.ownerSha)&&before.contractSha.equals(after.contractSha)
                    &&before.authorizationSha.equals(after.authorizationSha)&&before.bindingSha.equals(after.bindingSha)
                    &&before.generation.equals(after.generation)&&before.instance.equals(after.instance)
                    &&before.displayId==after.displayId&&before.windowId==after.windowId
                    &&before.links.get(action.nodeId).hrefResolved.equals(after.url)&&after.epoch>before.epoch,
                    "actual same-lease detail navigation does not match the observed source link");
            need(before.captureEnded>=0&&before.captureEnded<=dispatchBefore&&dispatchBefore<=dispatchAfter
                    &&dispatchAfter<=after.captureStarted,"actual monotonic dispatch/capture order required");
            try{
                need(before.observedArmRaw!=null&&after.sourceCaptureRaw!=null,"actual ARM and destination capture required");
                JSONObject arm=new JSONObject(before.observedArmRaw),destination=new JSONObject(after.sourceCaptureRaw);
                need(nativeModelRunId.equals(arm.get("model_run_id"))
                        &&before.links.get(action.nodeId).path.equals(arm.get("anchor_dom_path")),"ARM belongs to another actual model action");
                Object rawNavigation=destination.get("observed_link_navigation");
                need(rawNavigation instanceof JSONObject,"actual helper navigation event absent or incomplete");
                JSONObject verdict=org.trillionnium.hepta.webprotocol.WebObservedNavigation.verifyNavigation(
                        arm,(JSONObject)rawNavigation,destination,dispatchBefore,dispatchAfter);
                return new Navigation(before,after,nativeModelRunId,dispatchBefore,dispatchAfter,action,jsonMap(verdict));
            }catch(Exception invalid){
                throw new IllegalArgumentException("actual typed same-lease link navigation not verified",invalid);
            }
        }
        boolean matches(WebShoppingDomain now){
            return now!=null&&task.equals(now.taskId)&&owner.equals(now.ownerSha)&&contract.equals(now.contractSha)
                    &&authorization.equals(now.authorizationSha)&&binding.equals(now.bindingSha)&&generation.equals(now.generation)
                    &&instance.equals(now.instance)&&url.equals(now.url)&&display==now.displayId&&window==now.windowId&&now.epoch>=targetEpoch;
        }
        Map<String,Object> evidence(){return new LinkedHashMap<String,Object>(evidence);}
    }
    private static PhoneObservation.Node uniqueClick(PhoneObservation frame,WebNativeGeometry geometry,MiPublicProductPage.Link link)throws Exception{
        List<PhoneObservation.Node> matches=new ArrayList<PhoneObservation.Node>();
        for(PhoneObservation.Node node:frame.nodes)if(link.id.equals(node.viewId))matches.add(node);
        if(matches.size()!=1)return null;PhoneObservation.Node node=matches.get(0);
        if(!nativeVisible(frame,geometry,node)||!node.clickable||node.editable||node.password||node.scrollable)return null;
        String own=node.text.isEmpty()?node.description:node.text;
        if(!own.isEmpty())return link.label.equals(own)?node:null;
        ObservedChildText.Result child=node.childText;
        if(!"derived".equals(child.status)||child.truncated||!child.sourcesComplete||child.sources.isEmpty()
                ||!child.rootSignature.matches("[0-9a-f]{64}")||!child.bind(child.rootSignature).equals(node.observedAppTreeSignature))return null;
        Set<String> hashes=new HashSet<String>();for(String text:link.visibleTexts)hashes.add(WebEvidenceJson.sha(text));
        boolean model=false;for(ObservedChildText.Source source:child.sources){
            if(!source.descendantPath.matches("[0-9]+(?:/[0-9]+){0,3}")
                    ||!("text".equals(source.property)||"description".equals(source.property))
                    ||source.nodeSignature==null||!source.nodeSignature.matches("[0-9a-f]{64}")||!hashes.contains(source.textSha256))return null;
            if(WebEvidenceJson.sha(link.label).equals(source.textSha256))model=true;
        }
        return model?node:null;
    }
    private static PhoneObservation.Node uniqueReadable(PhoneObservation frame,WebNativeGeometry geometry,String label){
        List<PhoneObservation.Node> matches=new ArrayList<PhoneObservation.Node>();
        for(PhoneObservation.Node node:frame.nodes)if(label.equals(node.text.isEmpty()?node.description:node.text))matches.add(node);
        if(matches.size()!=1)return null;PhoneObservation.Node node=matches.get(0);
        return nativeVisible(frame,geometry,node)&&!node.password&&!node.editable?node:null;
    }
    private static boolean nativeVisible(PhoneObservation frame,WebNativeGeometry geometry,PhoneObservation.Node node){
        return WebEvidenceProtocol.HELPER_PACKAGE.equals(node.packageName)&&node.enabled
                &&node.observedAppTreeSignature!=null&&node.observedAppTreeSignature.matches("[0-9a-f]{64}")
                &&geometry.contains(node.bounds.left,node.bounds.top,node.bounds.right,node.bounds.bottom)
                &&inside(frame.windowMetadata.rootBounds(),node)&&inside(frame.windowMetadata.windowBounds(),node)
                &&node.bounds.left>=0&&node.bounds.top>=0&&node.bounds.right<=frame.width&&node.bounds.bottom<=frame.height;
    }
    private static boolean inside(int[] r,PhoneObservation.Node node){
        return r!=null&&r.length==4&&r[0]<=node.bounds.left&&r[1]<=node.bounds.top&&node.bounds.right<=r[2]&&node.bounds.bottom<=r[3];
    }
    private static Map<String,Object> nodeEvidence(PhoneObservation.Node node){
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("node_id",node.id);out.put("native_view_id",node.viewId);
        out.put("native_class",node.className);out.put("native_label",node.label());out.put("node_app_tree_sha256",node.observedAppTreeSignature);
        out.put("native_bounds",Arrays.asList(node.bounds.left,node.bounds.top,node.bounds.right,node.bounds.bottom));return out;
    }
    private static Map<String,Object> jsonMap(JSONObject value)throws Exception{
        Map<String,Object> out=new LinkedHashMap<String,Object>();java.util.Iterator<String> keys=value.keys();
        while(keys.hasNext()){String key=keys.next();out.put(key,jsonValue(value.get(key),0));}return out;
    }
    private static Object jsonValue(Object value,int depth)throws Exception{
        need(depth<=32,"bounded JSON evidence nesting");
        if(value==JSONObject.NULL)return null;
        if(value instanceof JSONObject){
            Map<String,Object> out=new LinkedHashMap<String,Object>();java.util.Iterator<String> keys=((JSONObject)value).keys();
            while(keys.hasNext()){String key=keys.next();out.put(key,jsonValue(((JSONObject)value).get(key),depth+1));}return out;
        }
        if(value instanceof org.json.JSONArray){
            List<Object> out=new ArrayList<Object>();org.json.JSONArray a=(org.json.JSONArray)value;
            for(int i=0;i<a.length();i++)out.add(jsonValue(a.get(i),depth+1));return out;
        }
        need(value instanceof String||value instanceof Boolean||value instanceof Number,"JSON scalar evidence required");return value;
    }
    private static void need(boolean ok,String message){if(!ok)throw new IllegalArgumentException(message);}
}
