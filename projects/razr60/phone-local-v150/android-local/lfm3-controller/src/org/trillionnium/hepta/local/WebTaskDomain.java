package org.trillionnium.hepta.local;

import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/** One of two actual page providers, with one immutable OWNER/site/lease binding. No dispatch API. */
final class WebTaskDomain {
    final String taskId,ownerSha,authorizationSha,observationId,stateSha,generation,instance,url,phase,pageKey;
    final int displayId,windowId;
    final long epoch;
    final Set<String> clickIds;
    final Map<String,String> editValues;
    final WebFlightDomain flight;
    final WebShoppingDomain shopping;
    private WebTaskDomain(WebFlightDomain value){
        flight=value;shopping=null;taskId=value.taskId;ownerSha=value.ownerSha;authorizationSha=value.authorizationSha;
        observationId=value.observationId;stateSha=value.stateSha;generation=value.generation;instance=value.instance;
        url=value.url;phase=value.phase;pageKey=value.pageKey;displayId=value.displayId;windowId=value.windowId;epoch=value.epoch;
        clickIds=value.clickIds;editValues=value.editValues;
    }
    private WebTaskDomain(WebShoppingDomain value){
        flight=null;shopping=value;taskId=value.taskId;ownerSha=value.ownerSha;authorizationSha=value.authorizationSha;
        observationId=value.observationId;stateSha=value.stateSha;generation=value.generation;instance=value.instance;
        url=value.url;phase=value.phase;pageKey=value.pageKey;displayId=value.displayId;windowId=value.windowId;epoch=value.epoch;
        clickIds=value.clickIds;editValues=Collections.emptyMap();
    }
    static WebTaskDomain observed(String task,WebTaskPurpose purpose,TaskAuthorization.Gate auth,
            PhoneObservation frame,WebEvidenceReceipt receipt,JSONObject binding)throws Exception{
        String sha=requireBound(task,purpose,auth,frame,receipt,binding);
        return purpose.flight!=null?new WebTaskDomain(WebFlightDomain.observed(task,purpose.flight,auth,frame,receipt,sha)):
                new WebTaskDomain(WebShoppingDomain.observed(task,purpose.shopping,auth,frame,receipt,binding));
    }
    static WebTaskDomain waiting(String task,WebTaskPurpose purpose,TaskAuthorization.Gate auth,
            PhoneObservation frame,WebEvidenceReceipt receipt,JSONObject binding)throws Exception{
        String sha=requireBound(task,purpose,auth,frame,receipt,binding);
        return purpose.flight!=null?new WebTaskDomain(WebFlightDomain.waiting(task,purpose.flight,auth,frame,receipt,sha)):
                new WebTaskDomain(WebShoppingDomain.waiting(task,purpose.shopping,auth,frame,receipt,binding));
    }
    private static String requireBound(String task,WebTaskPurpose purpose,TaskAuthorization.Gate auth,
            PhoneObservation frame,WebEvidenceReceipt receipt,JSONObject binding)throws Exception{
        WebTaskPurpose derived=WebTaskPurpose.requireBinding(binding);
        need(purpose!=null&&auth!=null&&frame!=null&&receipt!=null&&task.equals(auth.taskId)
                &&task.equals(binding.get("task_id"))&&purpose.owner.equals(derived.owner)
                &&purpose.contractSha256.equals(derived.contractSha256)&&purpose.kind.equals(derived.kind)
                &&purpose.sitePolicySha256.equals(derived.sitePolicySha256)
                &&purpose.ownerSha256.equals(auth.authorization.instructionSha256)
                &&WebEvidenceBinding.canonical(new JSONObject(auth.authorization.evidence())).equals(
                        WebEvidenceBinding.canonical(binding.getJSONObject("authorization"))),
                "same original OWNER, actual authority and compiled site purpose required");
        need(WebEvidenceProtocol.HELPER_VERSION_CODE==6&&"hepta.web-helper.binding.v4".equals(binding.get("schema"))
                &&WebEvidenceJson.number(binding.getJSONObject("helper_identity"),"version_code")==6,
                "current code6/v4 helper binding required");
        JSONObject bg=binding.getJSONObject("background");
        need(bg.getJSONArray("selected_packages").length()==1
                &&WebEvidenceProtocol.HELPER_PACKAGE.equals(bg.getJSONArray("selected_packages").get(0))
                &&frame.backgroundGeneration!=null&&frame.backgroundGeneration.equals(bg.get("generation"))
                &&receipt.displayId>0&&WebEvidenceJson.number(bg,"display_id")==receipt.displayId,
                "same explicit single-helper background lease required");
        String sha=WebEvidenceBinding.sha256(binding);
        need(sha.equals(receipt.bindingSha),"actual bound helper reply required");return sha;
    }
    WebTaskDomain withObservedLinkArm(JSONObject actualArm)throws Exception{
        need(shopping!=null,"observed link ARM is only available to the current shopping provider");
        return new WebTaskDomain(shopping.withObservedLinkArm(actualArm));
    }
    WebTaskDomain withNavigation(WebShoppingDomain.Navigation navigation){
        need(shopping!=null&&navigation!=null&&navigation.matches(shopping),"same task product navigation required");
        return new WebTaskDomain(shopping.withNavigation(navigation));
    }
    WebTaskDomain withFlightProgress(WebFlightProgress progress)throws Exception{
        need(flight!=null&&progress!=null&&progress.matches(flight),"same task flight progression required");
        return new WebTaskDomain(flight.withProgress(progress));
    }
    boolean queryDispatched(){return flight!=null&&flight.queryDispatched();}
    boolean resultReady(){return shopping!=null&&shopping.resultReady();}
    Map<String,Object> resultRecord(){
        need(resultReady(),"actual public result and model navigation are missing");return shopping.resultRecord();
    }
    Map<String,Object> evidence(){return flight!=null?flight.evidence():shopping.evidence();}
    /** A bounded view for the local model; the complete proof remains private. */
    Map<String,Object> promptEvidence(){
        Map<String,Object> full=evidence(),out=new java.util.LinkedHashMap<String,Object>();
        out.put("schema","hepta.web-domain-model-view.v1");out.put("source","current_independently_verified_web_domain");
        out.put("kind",flight!=null?"csair_public_flight":"mi_public_product");
        out.put("observation_id",observationId);out.put("phase",phase);out.put("current_native_url",url);
        out.put("allowed_click_ids",new java.util.ArrayList<String>(new java.util.TreeSet<String>(clickIds)));
        out.put("exact_edit_values",new java.util.TreeMap<String,String>(editValues));
        java.util.List<Map<String,Object>> controls=new java.util.ArrayList<Map<String,Object>>();
        for(String id:new java.util.TreeSet<String>(clickIds)){
            Map<String,Object> control=new java.util.LinkedHashMap<String,Object>();control.put("node_id",id);
            control.put("purpose",flight!=null?flight.purpose(id):"open_observed_official_product_detail");controls.add(control);
        }
        out.put("current_controls",controls);
        for(String key:new String[]{"next_goal","query_control_withheld","query_attempted","query_executed",
                "server_query_completed","query_retry_permitted","same_frame_public_price_observed","model_navigation_confirmed",
                "result_ready_for_completion_gate","missing"})
            if(full.containsKey(key))out.put(key,full.get(key));
        out.put("current_result_ready",resultReady());out.put("whole_scene_included",false);
        out.put("private_full_evidence_retained",true);out.put("grants_tool_authority",false);
        try{out.put("private_full_evidence_sha256",org.trillionnium.hepta.webprotocol.WebDomCanonical.sha256(new JSONObject(full)));}
        catch(Exception malformed){throw new IllegalStateException("current web domain proof cannot be projected",malformed);}
        return out;
    }
    Set<String> clicks(Set<String> original){return flight!=null?flight.clicks(original):shopping.clicks(original);}
    Set<String> edits(Set<String> original){return flight!=null?flight.edits(original):shopping.edits(original);}
    Set<String> openPackages(Set<String> original){return flight!=null?flight.openPackages(original):shopping.openPackages(original);}
    <T> Map<String,T> noNodeActions(Map<String,T> original){return flight!=null?flight.noNodeActions(original):shopping.noNodeActions(original);}
    Set<String> toolMask(Set<String> original){return flight!=null?flight.toolMask(original):shopping.toolMask(original);}
    void requireCurrent(ActionDecision action){if(flight!=null)flight.requireCurrent(action);else shopping.requireCurrent(action);}
    private static void need(boolean yes,String reason){WebEvidenceJson.need(yes,reason);}
}
