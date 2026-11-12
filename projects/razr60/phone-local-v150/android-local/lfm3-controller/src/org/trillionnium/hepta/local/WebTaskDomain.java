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
        need(WebEvidenceProtocol.HELPER_VERSION_CODE==5&&"hepta.web-helper.binding.v3".equals(binding.get("schema"))
                &&WebEvidenceJson.number(binding.getJSONObject("helper_identity"),"version_code")==5,
                "current code5/v3 helper binding required");
        JSONObject bg=binding.getJSONObject("background");
        need(bg.getJSONArray("selected_packages").length()==1
                &&WebEvidenceProtocol.HELPER_PACKAGE.equals(bg.getJSONArray("selected_packages").get(0))
                &&frame.backgroundGeneration!=null&&frame.backgroundGeneration.equals(bg.get("generation"))
                &&receipt.displayId>0&&WebEvidenceJson.number(bg,"display_id")==receipt.displayId,
                "same explicit single-helper background lease required");
        String sha=WebEvidenceBinding.sha256(binding);
        need(sha.equals(receipt.bindingSha),"actual bound helper reply required");return sha;
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
    Set<String> clicks(Set<String> original){return flight!=null?flight.clicks(original):shopping.clicks(original);}
    Set<String> edits(Set<String> original){return flight!=null?flight.edits(original):shopping.edits(original);}
    Set<String> openPackages(Set<String> original){return flight!=null?flight.openPackages(original):shopping.openPackages(original);}
    <T> Map<String,T> noNodeActions(Map<String,T> original){return flight!=null?flight.noNodeActions(original):shopping.noNodeActions(original);}
    Set<String> toolMask(Set<String> original){return flight!=null?flight.toolMask(original):shopping.toolMask(original);}
    void requireCurrent(ActionDecision action){if(flight!=null)flight.requireCurrent(action);else shopping.requireCurrent(action);}
    private static void need(boolean yes,String reason){WebEvidenceJson.need(yes,reason);}
}
