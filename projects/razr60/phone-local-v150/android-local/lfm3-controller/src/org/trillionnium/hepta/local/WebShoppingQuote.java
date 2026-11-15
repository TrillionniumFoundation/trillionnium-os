package org.trillionnium.hepta.local;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebMiActionRegion;
import org.trillionnium.hepta.webprotocol.WebSitePolicy;

/**
 * Current official-search-card quotation, never a detail/configuration/lowest-price
 * or purchase result. Values originate in one complete observed DOM card and its
 * independent native roles. Serialized evidence cannot construct a Completion.
 */
final class WebShoppingQuote {
    static final String SCHEMA="hepta.mi-visible-search-card-quote.v1";
    private final String task,owner,contract,authorization,binding,generation,instance,url,observation,state;
    private final int display,window;
    private final long epoch,captureStarted,captureEnded;
    private final String captureRaw,frameRaw,nativeRaw,windowsRaw,targetPath,readProofSha,nativeCaptureDomSha;
    private final String completionFrameSha,semanticSha;
    private final Map<String,Object> record;

    private WebShoppingQuote(WebShoppingDomain domain,PhoneObservation frame,WebEvidenceReceipt receipt,
            WebRegionNativeBridge bridge,JSONObject readProof,WebShoppingQuote prior)throws Exception{
        need(domain!=null&&frame!=null&&receipt!=null&&bridge!=null
                &&"official_public_search".equals(domain.phase)&&WebSitePolicy.INITIAL_URL.equals(domain.url)
                &&domain.observationId.equals(frame.id)&&domain.stateSha.equals(frame.treeSha256)
                &&domain.bindingSha.equals(receipt.bindingSha)&&domain.instance.equals(receipt.instance)
                &&domain.epoch==receipt.epoch&&domain.displayId==receipt.displayId&&domain.windowId==receipt.windowId,
                "same current search-card domain, frame and captured reply required");
        task=domain.taskId;owner=domain.ownerSha;contract=domain.contractSha;authorization=domain.authorizationSha;
        binding=domain.bindingSha;generation=domain.generation;instance=domain.instance;url=domain.url;
        observation=domain.observationId;state=domain.stateSha;display=domain.displayId;window=domain.windowId;epoch=domain.epoch;
        captureStarted=receipt.started;captureEnded=receipt.ended;
        JSONObject capture=receipt.capture(),jsonFrame=frame.toJson();
        WebMiActionRegion region=WebMiActionRegion.read(receipt.dom());
        JSONObject bridgeEvidence=bridge.evidence();
        need(receipt.stability()!=null&&receipt.stability().region!=null
                &&region.sameRegion(receipt.stability().region)&&bridge.anchorDomPath.equals(region.anchorPath)
                &&bridge.regionRoot.equals(region.rootPath)&&frame.id.equals(bridgeEvidence.get("source_observation_id"))
                &&frame.treeSha256.equals(bridgeEvidence.get("source_observation_state_sha256")),"same complete selected card and native-role bridge required");
        frameRaw=WebDomCanonical.canonical(jsonFrame);captureRaw=WebDomCanonical.canonical(capture);
        completionFrameSha=TaskCompletionGate.webFrameSha(completionFrame(frame));
        need(completionFrameSha!=null,"complete final-frame representation required");
        if(prior==null){
            need(readProof!=null&&"hepta.mi-search-readonly-observation-bracket.v1".equals(readProof.get("schema"))
                    &&"private_service_snapshot_and_live_complete_native_traversal".equals(readProof.get("source"))
                    &&task.equals(readProof.get("task_id"))&&binding.equals(readProof.get("binding_sha256"))
                    &&instance.equals(readProof.get("webview_instance"))&&epoch==readProof.getLong("navigation_epoch")
                    &&display==readProof.getInt("display_id")&&window==readProof.getInt("window_id")
                    &&WebDomCanonical.same(readProof.getJSONObject("last_observation"),jsonFrame)
                    &&capture.get("challenge").equals(readProof.get("last_capture_challenge"))
                    &&receipt.domSha.equals(readProof.getJSONObject("dom").get("last_after_sha256"))
                    &&capture.get("before_dom_sha256").equals(readProof.getJSONObject("dom").get("last_before_sha256")),
                    "private service read proof belongs to another current capture or native frame");
            for(String flag:new String[]{"original_target_obtained_before_graph_recycling","original_node_ref_identity_preserved",
                    "actual_ancestor_chain_refreshed","two_interactive_window_reads_equal","complete_native_snapshot_structure_replayed"})
                need(Boolean.TRUE.equals(readProof.get(flag)),"incomplete live private read proof: "+flag);
            for(String flag:new String[]{"native_invocation_entered","action_permit_created","grants_action_authority","business_verified"})
                need(Boolean.FALSE.equals(readProof.get(flag)),"readonly source must not claim an action or business result");
            need(frame.capturedElapsedMillis==readProof.getLong("last_ax_captured_elapsed_ms")
                    &&captureEnded<=readProof.getLong("started_elapsed_ms")
                    &&readProof.getLong("started_elapsed_ms")<=readProof.getLong("checked_elapsed_ms"),
                    "actual native/capture verification clocks differ");
            JSONObject nativeProof=readProof.getJSONObject("native"),live=readProof.getJSONObject("live_native_recheck");
            targetPath=nativeProof.getString("target_native_path");
            need(targetPath.equals(bridge.anchor.nativeTreePath)&&targetPath.equals(live.get("target_native_path"))
                    &&WebDomCanonical.same(nativeProof.getJSONArray("after"),live.getJSONArray("before")),
                    "native roles differ from the original private snapshot");
            JSONArray rows=nativeProof.getJSONArray("after");
            WebShoppingObservationStability.requireCompleteObservation(jsonFrame,rows);
            WebShoppingObservationStability.compareNative(rows,live.getJSONArray("after"),targetPath);
            nativeRaw=WebDomCanonical.canonical(rows);
            JSONObject windows=readProof.getJSONObject("interactive_windows_after");
            need(WebDomCanonical.same(readProof.getJSONObject("interactive_windows_before"),windows)
                    &&display==windows.getInt("display_id")&&window==windows.getInt("target_window_id")
                    &&Boolean.FALSE.equals(windows.get("observed_upper_or_same_layer_overlap"))
                    &&Boolean.FALSE.equals(windows.get("ime_window_observed")),
                    "original selected-display interactive-window readback required");
            windowsRaw=WebDomCanonical.canonical(windows);readProofSha=WebDomCanonical.sha256(readProof);
            nativeCaptureDomSha=receipt.domSha;
        }else{
            need(readProof==null&&prior.sameAuthority(this)&&frameRaw.equals(prior.frameRaw)
                    &&bridge.anchor.nativeTreePath.equals(prior.targetPath)
                    &&prior.captureEnded<=captureStarted
                    &&WebShoppingObservationStability.supportsCaptures(new JSONObject(prior.captureRaw),capture),
                    "fresh pre-done capture must preserve the original verified quote and exact native frame");
            targetPath=prior.targetPath;nativeRaw=prior.nativeRaw;windowsRaw=prior.windowsRaw;
            readProofSha=prior.readProofSha;nativeCaptureDomSha=prior.nativeCaptureDomSha;
        }
        JSONObject semantic=new JSONObject().put("binding_sha256",binding).put("background_generation",generation)
                .put("webview_instance",instance).put("navigation_epoch",epoch).put("display_id",display).put("window_id",window)
                .put("selected_region",region.evidence()).put("native_target_path",targetPath);
        semanticSha=WebDomCanonical.sha256(semantic);
        if(prior!=null)need(prior.semanticSha.equals(semanticSha),"fresh capture changed the actual selected quote");
        Map<String,Object> value=new LinkedHashMap<String,Object>();
        value.put("schema",SCHEMA);value.put("task_id",task);value.put("owner_sha256",owner);value.put("contract_sha256",contract);
        value.put("authorization_sha256",authorization);value.put("binding_sha256",binding);value.put("background_generation",generation);
        value.put("webview_instance",instance);value.put("navigation_epoch",epoch);value.put("display_id",display);value.put("window_id",window);
        value.put("observation_id",observation);value.put("observation_state_sha256",state);value.put("committed_url",url);
        value.put("capture_started_elapsed_ms",captureStarted);value.put("capture_ended_elapsed_ms",captureEnded);
        value.put("dom_sha256",receipt.domSha);value.put("capture_challenge",capture.getString("challenge"));
        value.put("native_read_proof_sha256",readProofSha);value.put("native_read_capture_dom_sha256",nativeCaptureDomSha);
        value.put("fresh_capture_rechecked_against_same_native_frame",prior!=null);
        value.put("model_raw",region.modelLabel);value.put("displayed_price_raw",region.currentPriceRaw);
        value.put("amount_decimal",region.currentAmountDecimal);value.put("currency_raw","元");value.put("currency","CNY");
        value.put("comparison_displayed_price_raw",region.comparisonPriceRaw);value.put("comparison_amount_decimal",region.comparisonAmountDecimal);
        value.put("comparison_price_scope","observed_del_descendant_not_current_quote");
        value.put("official_product_link",region.hrefResolved);value.put("observed_href_raw",region.hrefRaw);
        value.put("observed_variant",region.observedVariant);value.put("anchor_dom_path",region.anchorPath);
        value.put("current_price_dom_path",region.currentPricePath);value.put("comparison_price_dom_path",region.comparisonPricePath);
        value.put("native_anchor_path",targetPath);value.put("selected_region_sha256",region.fullRegionSha256);
        value.put("selected_region_ancestor_sha256",region.ancestorSha256);value.put("native_region_bridge_sha256",WebDomCanonical.sha256(bridgeEvidence));
        value.put("quote_semantic_sha256",semanticSha);value.put("price_scope","displayed_current_official_search_card_quote");
        value.put("same_frame_native_labels_verified",true);value.put("complete_private_native_read_verified",true);
        value.put("price_or_SKU_filled_from_goal",false);value.put("bootstrap_search_is_model_query",false);
        value.put("model_navigation_verified",false);value.put("detail_price_verified",false);value.put("lowest_price_verified",false);
        value.put("exact_configuration_verified",false);value.put("specifications_verified",false);value.put("order_completed",false);
        value.put("grants_tool_authority",false);value.put("business_verified",false);value.put("final_native_and_cleanup_gates_verified",false);
        value.put("display_summary","已核对小米官网搜索页当前商品卡："+region.modelLabel+"；展示价人民币 "+region.currentAmountDecimal
                +" 元，划线对比价 "+region.comparisonAmountDecimal+" 元。官方链接："+region.hrefResolved+"。核对范围为当前搜索卡展示报价。");
        record=Collections.unmodifiableMap(value);
    }
    static WebShoppingQuote fromRead(WebShoppingDomain domain,PhoneObservation frame,WebEvidenceReceipt receipt,
            WebRegionNativeBridge bridge,JSONObject proof)throws Exception{
        return new WebShoppingQuote(domain,frame,receipt,bridge,proof,null);
    }
    WebShoppingQuote rechecked(WebShoppingDomain domain,PhoneObservation frame,WebEvidenceReceipt receipt,
            WebRegionNativeBridge bridge)throws Exception{
        need(matchesAuthorityFrame(domain,frame),"fresh quote belongs to another native frame");
        return new WebShoppingQuote(domain,frame,receipt,bridge,null,this);
    }
    private boolean sameAuthority(WebShoppingQuote x){
        return x!=null&&task.equals(x.task)&&owner.equals(x.owner)&&contract.equals(x.contract)&&authorization.equals(x.authorization)
                &&binding.equals(x.binding)&&generation.equals(x.generation)&&instance.equals(x.instance)&&url.equals(x.url)
                &&display==x.display&&window==x.window&&epoch==x.epoch;
    }
    private boolean matchesAuthorityFrame(WebShoppingDomain d,PhoneObservation f)throws Exception{
        return matches(d)&&f!=null&&frameRaw.equals(WebDomCanonical.canonical(f.toJson()));
    }
    boolean matches(WebShoppingDomain d){
        return d!=null&&task.equals(d.taskId)&&owner.equals(d.ownerSha)&&contract.equals(d.contractSha)&&authorization.equals(d.authorizationSha)
                &&binding.equals(d.bindingSha)&&generation.equals(d.generation)&&instance.equals(d.instance)&&url.equals(d.url)
                &&observation.equals(d.observationId)&&state.equals(d.stateSha)&&display==d.displayId&&window==d.windowId&&epoch==d.epoch;
    }
    Map<String,Object> resultRecord(){return new LinkedHashMap<String,Object>(record);}
    Map<String,Object> modelView(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        for(String key:new String[]{"schema","model_raw","displayed_price_raw","amount_decimal","currency_raw","currency",
                "comparison_displayed_price_raw","comparison_price_scope","official_product_link","observed_variant","price_scope",
                "detail_price_verified","lowest_price_verified","order_completed","display_summary"})out.put(key,record.get(key));
        out.put("source","current_same_card_DOM_and_private_native_readback");return out;
    }

    /** Constructed only after the real accepted no-effect model done outcome. */
    static final class Pending {
        private final TaskCompletionGate gate;
        private final WebShoppingQuote before;
        private final ActionDecision action;
        private final String run;
        private final long start,end;
        private boolean consumed;
        private Pending(TaskCompletionGate gate,WebShoppingQuote before,ActionDecision action,String run,long start,long end){
            this.gate=gate;this.before=before;this.action=action;this.run=run;this.start=start;this.end=end;
        }
        static Pending fromOutcome(TaskCompletionGate gate,WebTaskDomain source,ActionDecision action,String run,
                boolean accepted,boolean dispatched,boolean stale,long start,long end){
            if(source==null||source.shopping==null||source.shopping.searchQuote==null
                    ||action==null||!"done".equals(action.action)||!"success".equals(action.status)
                    ||!accepted||dispatched||stale)return null;
            WebShoppingQuote quote=source.shopping.searchQuote;
            need(gate!=null&&source.resultReady()&&quote.matches(source.shopping)&&action.toolChildOrigin==null
                    &&quote.observation.equals(action.observationId)&&WebEvidenceProtocol.HELPER_PACKAGE.equals(action.packageName)
                    &&run!=null&&run.matches("[0-9a-f]{32}")&&quote.captureEnded<=start&&start<=end,
                    "actual accepted same-frame no-effect model done required");
            return new Pending(gate,quote,action,run,start,end);
        }
        JSONObject evidence()throws Exception{
            return new JSONObject().put("schema","hepta.mi-search-quote-model-done.v1").put("task_id",before.task)
                    .put("binding_sha256",before.binding).put("model_run_id",run).put("before_observation_id",before.observation)
                    .put("dispatch_before_elapsed_ms",start).put("dispatch_after_elapsed_ms",end)
                    .put("accepted",true).put("dispatched",false).put("stale",false).put("model_issued",true)
                    .put("quote_semantic_sha256",before.semanticSha).put("business_verified",false);
        }
        Completion complete(TaskCompletionGate expected,WebTaskDomain current,ActionDecision actual,String actualRun,
                PhoneObservation beforeFrame,PhoneObservation afterFrame)throws Exception{
            need(!consumed,"quote done continuation already consumed");consumed=true;
            need(expected==gate&&actual==action&&run.equals(actualRun)&&current!=null&&current.shopping!=null
                    &&current.shopping.searchQuote!=null&&current.resultReady()
                    &&beforeFrame!=null&&before.frameRaw.equals(WebDomCanonical.canonical(beforeFrame.toJson())),
                    "same actual done request and original native frame required");
            WebShoppingQuote after=current.shopping.searchQuote;
            need(after.matchesAuthorityFrame(current.shopping,afterFrame)&&before.sameAuthority(after)
                    &&before.semanticSha.equals(after.semanticSha)&&before.targetPath.equals(after.targetPath)
                    &&end<=after.captureStarted&&before.windowsRaw.equals(after.windowsRaw),
                    "final quote, lease, epoch, native target or interactive windows changed");
            JSONObject proof=WebShoppingObservationStability.compareObservationBracket(before.task,
                    new JSONObject(before.frameRaw),new JSONArray(before.nativeRaw),new JSONObject(after.frameRaw),new JSONArray(after.nativeRaw),
                    new JSONObject(before.captureRaw),new JSONObject(after.captureRaw),before.targetPath);
            proof.put("schema","hepta.mi-search-quote-final-read.v1").put("actual_done",evidence())
                    .put("before_native_read_proof_sha256",before.readProofSha).put("after_native_read_proof_sha256",after.readProofSha)
                    .put("before_quote",new JSONObject(before.resultRecord())).put("after_quote",new JSONObject(after.resultRecord()))
                    .put("interactive_windows",new JSONObject(after.windowsRaw)).put("all_non_recommendation_native_records_equal",true)
                    .put("complete_before_and_after_frames_included",true).put("whole_tree_equality_claimed",false)
                    .put("query_or_purchase_proved",false).put("business_verified",false);
            return new Completion(gate,current,after,run,WebDomCanonical.canonical(proof));
        }
    }
    /** A private in-process one-shot proof. JSON/evidence cannot call its constructor. */
    static final class Completion {
        private final TaskCompletionGate gate;
        private final WebTaskDomain domain;
        private final WebShoppingQuote after;
        private final String run,proofRaw,proofSha;
        private boolean consumed;
        private Completion(TaskCompletionGate gate,WebTaskDomain domain,WebShoppingQuote after,String run,String proof)throws Exception{
            this.gate=gate;this.domain=domain;this.after=after;this.run=run;proofRaw=proof;proofSha=WebEvidenceJson.sha(proof);
        }
        JSONObject evidence()throws Exception{return new JSONObject(proofRaw);}
        Map<String,Object> summary(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();
            out.put("schema","hepta.mi-search-quote-completion-scope.v1");out.put("task_id",after.task);
            out.put("model_run_id",run);out.put("observation_id",after.observation);out.put("binding_sha256",after.binding);
            out.put("full_final_read_proof_sha256",proofSha);out.put("complete_frames_and_non_recommendation_native_compared",true);
            out.put("whole_tree_equality_claimed",false);out.put("grants_tool_authority",false);out.put("business_verified",false);return out;
        }
        synchronized boolean consume(TaskCompletionGate expected,WebTaskDomain current,NotesCompletionEvidence.Frame frame,String modelRun){
            boolean first=!consumed;consumed=true;
            return first&&expected==gate&&current==domain&&domain.shopping!=null&&domain.shopping.searchQuote==after
                    &&after.matches(domain.shopping)&&run.equals(modelRun)
                    &&Objects.equals(after.completionFrameSha,TaskCompletionGate.webFrameSha(frame));
        }
    }
    private static NotesCompletionEvidence.Frame completionFrame(PhoneObservation o){
        if(o==null)return null;
        java.util.List<NotesCompletionEvidence.Node> nodes=new java.util.ArrayList<NotesCompletionEvidence.Node>();
        for(PhoneObservation.Node n:o.nodes){
            String label=n.label();
            if(n.text.trim().isEmpty()&&n.description.trim().isEmpty()&&(n.childText.truncated||!"derived".equals(n.childText.status)))label="";
            nodes.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,label,n.viewId,n.inputTextSha256,
                    new int[]{n.bounds.left,n.bounds.top,n.bounds.right,n.bounds.bottom},n.editable,n.clickable,n.scrollable,n.enabled,n.password,n.childText,n.observedAppTreeSignature,n.className,n.nativeTreePath));
        }
        return new NotesCompletionEvidence.Frame(o.id,o.packageName,o.windowId,o.windowMetadata.displayId==null?-1:o.windowMetadata.displayId,
                o.backgroundGeneration,o.windowMetadata.type==null?-1:o.windowMetadata.type,"observed".equals(o.windowMetadata.status),o.nodesTruncated,nodes);
    }
    private static void need(boolean ok,String reason){if(!ok)throw new IllegalArgumentException(reason);}
}
