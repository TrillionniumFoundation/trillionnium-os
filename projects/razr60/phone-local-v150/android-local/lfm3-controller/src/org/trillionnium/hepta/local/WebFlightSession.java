package org.trillionnium.hepta.local;

import android.content.Context;
import android.os.SystemClock;
import org.json.JSONObject;
import org.trillionnium.hepta.local.web.WebFlightGoal;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.Collections;
import java.util.UUID;

/** One actual OWNER/VD/helper lease; no implicit app selection, network method or UI macro. */
final class WebFlightSession {
    interface Observer { PhoneObservation observe()throws Exception; }
    static final class Cleanup {
        final boolean known;final JSONObject evidence;
        private Cleanup(boolean known,JSONObject evidence){this.known=known;this.evidence=evidence;}
    }
    final String taskId;
    final WebFlightGoal goal;
    final TaskAuthorization.Gate authorization;
    private final HeptaAccessibilityService service;
    private final BackgroundSession background;
    private final WebHelperIdentity controller,helper;
    private final WebEvidenceJournal journal;
    private final WebEvidenceClient client;
    private final HeptaAccessibilityService.Cancellation cancellation;
    private final TaskCompletionGate completion;
    private volatile WebFlightDomain domain;
    private volatile boolean retired,cleanupKnown;
    private volatile PhoneObservation current;
    private long dispatchCheckedAt;
    private String dispatchCheckedRun;
    private String dispatchCheckedAction;
    private final File evidence;

    static void validateSelection(String owner,BackgroundSession.Selection selection){
        WebFlightGoal goal=WebFlightGoal.parse(owner);
        boolean selected=selection!=null&&selection.allowedPackages.contains(WebEvidenceProtocol.HELPER_PACKAGE);
        if(goal==null){if(selected)throw new IllegalArgumentException("南航网页工具需要完整的公开查询目标；不会在未知任务中联网");return;}
        if(!goal.ownerContainsOpen||selection==null||!WebEvidenceProtocol.HELPER_PACKAGE.equals(selection.initialPackage)
                ||!selection.allowedPackages.equals(Collections.singletonList(WebEvidenceProtocol.HELPER_PACKAGE)))
            throw new IllegalArgumentException("请启用后台模式，并明确选择南航网页工具作为唯一任务应用");
        if(!goal.departureNotBefore(LocalDate.now()))throw new IllegalArgumentException("查询日期已过去，请指定今天或以后的实际日期");
    }
    static boolean supported(String owner){return WebFlightGoal.parse(owner)!=null;}
    static boolean hasUnreleased(Context context){return WebEvidenceJournal.hasUnreleased(context);}

    WebFlightSession(HeptaAccessibilityService service,String task,String owner,TaskAuthorization.Gate authorization,
                     BackgroundSession background,QualificationScopeConfig.FilesRoot filesRoot,File evidence,
                     TaskCompletionGate completion,HeptaAccessibilityService.Cancellation cancellation)throws Exception{
        goal=WebFlightGoal.parse(owner);validateSelection(owner,background==null?null:background.selection);
        need(goal!=null&&goal.ownerContainsOpen&&task.equals(authorization.taskId)&&completion!=null,"explicit flight contract required");
        authorization.authorization.requireOwner(owner);authorization.ready();
        need(authorization.authorization.allowedTools.equals(WebEvidenceProtocol.READ_ONLY_TOOLS)
                &&!authorization.authorization.requireFindAppBeforeOpen,"actual exact read-only tool authorization required");
        this.service=service;this.taskId=task;this.authorization=authorization;this.background=background;
        this.cancellation=cancellation;this.completion=completion;this.evidence=evidence;
        background.requireActive();need(background.ownerSha256.equals(goal.ownerSha256),"background OWNER differs");
        controller=WebHelperIdentity.read(service,WebEvidenceProtocol.CONTROLLER_PACKAGE);
        helper=WebHelperIdentity.read(service,WebEvidenceProtocol.HELPER_PACKAGE);
        WebHelperIdentity.requirePeer(service,controller,helper);
        JSONObject actual=background.evidence();
        JSONObject bg=new JSONObject().put("generation",background.generation).put("display_id",background.displayId())
                .put("display_name",background.displayName).put("boot_count",actual.get("boot_count"))
                .put("created_elapsed_ms",background.createdElapsed).put("expires_elapsed_ms",background.expiresElapsed)
                .put("selected_packages",new org.json.JSONArray(background.selection.allowedPackages));
        String session=UUID.randomUUID().toString().replace("-","")+UUID.randomUUID().toString().replace("-","");
        JSONObject attach=new JSONObject().put("task_id",task).put("controller_session_nonce",session)
                .put("owner",owner).put("owner_sha256",goal.ownerSha256).put("contract_sha256",goal.contractSha256)
                .put("authorization",new JSONObject(authorization.authorization.evidence()))
                .put("background",bg).put("controller_identity",controller.evidence).put("helper_identity",helper.evidence);
        JSONObject binding=WebEvidenceBinding.fromAttach(attach);
        journal=WebEvidenceJournal.create(service,filesRoot,evidence,binding);
        client=new WebEvidenceClient(service,controller,helper,binding,new WebEvidenceClient.Guard(){
            public void requireCurrent(boolean cleanup)throws Exception{
                filesRoot.unchanged(service);WebHelperIdentity.requirePeer(service,controller,helper);
                if(!cleanup){
                    need(!retired&&!cancellation.isCancelled(),"web task retired");
                    service.requireTaskAuthorization(taskId,authorization);background.requireActive();
                }
            }
            public boolean cancelled(){return cancellation.isCancelled();}
        },journal);
        record("web-flight-owner.json",new JSONObject(goal.evidence()).put("task_id",task)
                .put("task_authorization_sha256",authorization.authorization.sha256).put("binding_sha256",journal.bindingSha)
                .put("task_local_date",LocalDate.now().toString()).put("background_selected_by_owner",true)
                .put("network_process_is_separate_helper",true).put("external_model",false));
    }
    void attach(long deadline)throws Exception{
        need(!retired,"web task retired");long end=Math.min(deadline,SystemClock.elapsedRealtime()+10000);
        client.connect(end);WebEvidenceReceipt response=client.attach(client.newAttach(end));
        record("web-helper-attached.json",response.callback());
    }
    PhoneObservation observe(PhoneObservation initial,Observer observer,long deadline)throws Exception{
        need(!retired&&!cancellation.isCancelled(),"web task retired");
        PhoneObservation before=initial;service.requireBackgroundObservation(taskId,before);
        WebEvidenceReceipt first=client.capture(deadline);
        if("state_changed".equals(first.status)){
            // At most one read-only retry, after a fresh AX window observation; never repeat an action.
            before=observer.observe();service.requireBackgroundObservation(taskId,before);first=client.capture(deadline);
            need("captured".equals(first.status)||"unavailable".equals(first.status)||"state_changed".equals(first.status),
                    "unknown reply after the single evidence retry");
        }
        if("unavailable".equals(first.status)||"state_changed".equals(first.status)){
            PhoneObservation after=observer.observe();service.requireBackgroundObservation(taskId,after);
            return publishWaiting(after,first,"initial_capture_not_stable");
        }
        need("captured".equals(first.status),"actual page capture unavailable");
        PhoneObservation after=observer.observe();service.requireBackgroundObservation(taskId,after);
        WebEvidenceReceipt last=client.capture(deadline);
        if("unavailable".equals(last.status)||"state_changed".equals(last.status))
            return publishWaiting(after,last,"final_capture_not_stable");
        need("captured".equals(last.status)&&sameFrame(before,after)
                &&first.instance.equals(last.instance)&&first.epoch==last.epoch&&first.url.equals(last.url)
                &&first.domRaw().equals(last.domRaw()),"AX/DOM bracket changed; no current page capability published");
        WebNativeGeometry firstGeometry=WebNativeGeometry.read(first.capture(),first.dom(),first.displayId,first.windowId);
        WebNativeGeometry lastGeometry=WebNativeGeometry.read(last.capture(),last.dom(),last.displayId,last.windowId);
        need(firstGeometry==null&&lastGeometry==null||firstGeometry!=null&&firstGeometry.same(lastGeometry),
                "native WebView geometry changed across the AX/DOM bracket");
        WebFlightDomain observed=WebFlightDomain.observed(taskId,goal,authorization,after,last,journal.bindingSha);
        record("web-frame-"+after.id+".json",new JSONObject(observed.evidence())
                .put("first_capture_request_nonce",first.callback().getString("request_nonce"))
                .put("last_capture_request_nonce",last.callback().getString("request_nonce"))
                .put("first_ax_observation_id",before.id).put("last_ax_observation_id",after.id)
                .put("ax_dom_capture_is_atomic",false).put("same_lease_epoch_and_equal_dom_bracket",true)
                .put("same_native_geometry_bracket",firstGeometry!=null)
                .put("native_geometry_sha256",lastGeometry==null?JSONObject.NULL:lastGeometry.fingerprint));
        current=after;domain=observed;completion.bindWebDomain(observed);
        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;
        return after;
    }
    private PhoneObservation publishWaiting(PhoneObservation frame,WebEvidenceReceipt receipt,String reason)throws Exception{
        WebFlightDomain waiting=WebFlightDomain.waiting(taskId,goal,authorization,frame,receipt,journal.bindingSha);
        record("web-frame-"+frame.id+".json",new JSONObject(waiting.evidence()).put("reason",reason)
                .put("capture_metadata_only",true).put("ax_dom_capture_is_atomic",false)
                .put("same_lease_epoch_and_equal_dom_bracket",false));
        current=frame;domain=waiting;completion.bindWebDomain(waiting);
        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;return frame;
    }
    void beforeModelAction(ActionDecision action,String run,long deadline)throws Exception{
        WebFlightDomain original=domain;PhoneObservation frame=current;
        need(original!=null&&frame!=null&&run!=null&&run.matches("[0-9a-f]{32}"),"current model-bound web action required");
        original.requireCurrent(action);service.requireTaskAuthorization(taskId,authorization);background.requireActive();
        if("wait".equals(action.action)||"done".equals(action.action)&&!"success".equals(action.status)){
            // These choices do not manipulate a page. A missing capture never
            // becomes click/type/success authority and never clears the journal.
            dispatchCheckedRun=run;dispatchCheckedAction=action.action+"\n"+(action.nodeId==null?"":action.nodeId);
            dispatchCheckedAt=SystemClock.elapsedRealtime();
            record("web-dispatch-"+run+".json",new JSONObject(original.evidence()).put("model_run_id",run)
                    .put("model_issued",true).put("action",action.action).put("no_page_effect",true)
                    .put("dispatched",false).put("source","current_restricted_model_choice"));
            return;
        }
        WebEvidenceReceipt fresh=client.capture(deadline);
        need("captured".equals(fresh.status),"document changed before action");
        WebFlightDomain rechecked=WebFlightDomain.observed(taskId,goal,authorization,frame,fresh,journal.bindingSha);
        need(original.instance.equals(rechecked.instance)&&original.epoch==rechecked.epoch
                &&original.pageKey.equals(rechecked.pageKey)&&original.clickIds.equals(rechecked.clickIds)
                &&original.editValues.equals(rechecked.editValues),"page target changed since model observation");
        rechecked.requireCurrent(action);
        dispatchCheckedRun=run;dispatchCheckedAction=action.action+"\n"+(action.nodeId==null?"":action.nodeId);
        dispatchCheckedAt=SystemClock.elapsedRealtime();
        record("web-dispatch-"+run+".json",new JSONObject(rechecked.evidence())
                .put("model_run_id",run).put("model_issued",true).put("action",action.action)
                .put("node_id",action.nodeId==null?JSONObject.NULL:action.nodeId)
                .put("original_dom_sha256",original.evidence().get("dom_sha256"))
                .put("fresh_capture_request_nonce",fresh.callback().getString("request_nonce"))
                .put("unchanged_semantic_region",true).put("whole_dom_equality_claimed",false)
                .put("dispatched",false).put("source","pre_dispatch_read_only_check_not_action_outcome"));
    }
    void requireDispatch(ActionDecision action,String run){
        WebFlightDomain d=domain;need(!retired&&d!=null&&run!=null&&run.equals(dispatchCheckedRun)
                &&(action.action+"\n"+(action.nodeId==null?"":action.nodeId)).equals(dispatchCheckedAction)
                &&SystemClock.elapsedRealtime()>=dispatchCheckedAt&&SystemClock.elapsedRealtime()-dispatchCheckedAt<=1500,
                "fresh exact web/model action evidence expired");
        d.requireCurrent(action);
    }
    boolean released(){return retired&&cleanupKnown;}
    synchronized void acceptReconciliation(Cleanup proof)throws Exception{
        need(proof!=null&&proof.known&&retired&&Boolean.TRUE.equals(proof.evidence.get("cleanup_known"))
                &&taskId.equals(proof.evidence.getString("task_id"))
                &&journal.bindingSha.equals(proof.evidence.getString("binding_sha256"))
                &&!hasUnreleased(service),"helper retirement proof does not match this original task");
        cleanupKnown=true;
    }
    void serviceRetired(){retired=true;domain=null;client.close();}
    Cleanup close(String reason){
        retired=true;domain=null;completion.clearWebDomain();
        try{
            if(!journal.attachWasPrepared()){
                journal.closeNeverAttached();cleanupKnown=true;
                return new Cleanup(true,new JSONObject().put("cleanup_known",true).put("no_attach_request_prepared",true)
                        .put("task_id",taskId).put("binding_sha256",journal.bindingSha));
            }
            WebEvidenceReceipt proof=client.closeLease(reason,SystemClock.elapsedRealtime()+10000);
            journal.closeKnown(proof);cleanupKnown=true;
            return new Cleanup(true,new JSONObject().put("cleanup_known",true).put("helper",proof.callback())
                    .put("task_id",taskId).put("binding_sha256",journal.bindingSha).put("business_verified",false));
        }catch(Exception unknown){
            try{return new Cleanup(false,new JSONObject().put("cleanup_known",false).put("task_id",taskId)
                    .put("binding_sha256",journal.bindingSha).put("error",HeptaAccessibilityService.limited(HeptaAccessibilityService.message(unknown),512))
                    .put("automatic_retry",false));}catch(Exception impossible){throw new IllegalStateException(impossible);}
        }finally{client.close();}
    }
    static Cleanup reconcile(Context context)throws Exception{
        if(!hasUnreleased(context))return new Cleanup(true,new JSONObject().put("cleanup_known",true).put("no_web_lease",true));
        WebEvidenceJournal original=WebEvidenceJournal.open(context);
        if(!original.attachWasPrepared()){original.closeNeverAttached();return new Cleanup(true,new JSONObject().put("cleanup_known",true).put("no_attach_request_prepared",true).put("task_id",original.taskId).put("binding_sha256",original.bindingSha));}
        JSONObject binding=original.binding();
        WebHelperIdentity controller=WebHelperIdentity.read(context,WebEvidenceProtocol.CONTROLLER_PACKAGE),helper=WebHelperIdentity.read(context,WebEvidenceProtocol.HELPER_PACKAGE);
        controller.requireRequest(binding.getJSONObject("controller_identity"));helper.requireRequest(binding.getJSONObject("helper_identity"));
        WebEvidenceClient client=new WebEvidenceClient(context,controller,helper,binding,new WebEvidenceClient.Guard(){
            public void requireCurrent(boolean cleanup)throws Exception{
                need(cleanup,"recovery is close-only; no old task action may resume");
                WebHelperIdentity.requirePeer(context,controller,helper);
            }
            public boolean cancelled(){return false;}
        },original);
        try{
            long deadline=SystemClock.elapsedRealtime()+10000;client.connect(deadline);
            WebEvidenceReceipt proof=client.closeLease("error",deadline);original.closeKnown(proof);
            return new Cleanup(true,new JSONObject().put("cleanup_known",true).put("helper",proof.callback())
                    .put("task_id",original.taskId).put("binding_sha256",original.bindingSha)
                    .put("automatic_resume",false).put("business_verified",false));
        }finally{client.close();}
    }
    private void record(String name,JSONObject value)throws Exception{
        need(name.matches("[A-Za-z0-9_.-]+"),"fixed evidence filename");MobiMindPrivateFiles.writeNew(new File(evidence,name),value.toString(2).getBytes(StandardCharsets.UTF_8));
    }
    private static boolean sameFrame(PhoneObservation a,PhoneObservation b){
        return a.packageName.equals(b.packageName)&&a.windowId==b.windowId&&a.rotation==b.rotation
                &&a.treeSha256.equals(b.treeSha256)&&a.state.appTreeSha256.equals(b.state.appTreeSha256)
                &&a.backgroundGeneration!=null&&a.backgroundGeneration.equals(b.backgroundGeneration)
                &&a.windowMetadata.displayId!=null&&a.windowMetadata.displayId.equals(b.windowMetadata.displayId);
    }
    private static void need(boolean condition,String reason){WebEvidenceJson.need(condition,reason);}
}
