package org.trillionnium.hepta.local;

import android.content.Context;
import android.os.SystemClock;
import org.json.JSONObject;
import org.trillionnium.hepta.local.web.WebFlightGoal;
import org.trillionnium.hepta.local.web.WebShoppingGoal;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebDomStability;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;
import org.trillionnium.hepta.webprotocol.WebObservedNavigation;
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
    final WebTaskPurpose purpose;
    private final JSONObject immutableBinding;
    final TaskAuthorization.Gate authorization;
    private final HeptaAccessibilityService service;
    private final BackgroundSession background;
    private final WebHelperIdentity controller,helper;
    private final WebEvidenceJournal journal;
    private final WebEvidenceClient client;
    private final HeptaAccessibilityService.Cancellation cancellation;
    private final TaskCompletionGate completion;
    private volatile WebTaskDomain domain;
    private volatile boolean retired,cleanupKnown;
    private volatile PhoneObservation current;
    private long dispatchCheckedAt;
    private String dispatchCheckedRun;
    private String dispatchCheckedAction;
    private final File evidence;
    private WebTaskDomain dispatchSource;
    private String dispatchSourceRun,dispatchSourceAction;
    private WebShoppingDomain.Navigation shoppingNavigation;
    private WebFlightProgress flightProgress;
    private final java.util.concurrent.atomic.AtomicBoolean nativeQueryEntered=new java.util.concurrent.atomic.AtomicBoolean();
    private PendingNavigation pendingNavigation;
    private WebShoppingQuote.Pending shoppingReadCompletion;
    private volatile ShoppingDispatch shoppingDispatch;
    private volatile WebEvidenceReceipt currentCapture;
    private volatile WebFlightNativeStability.Permit flightNativePermit;
    private volatile HeptaAccessibilityService.FlightNativeCheck flightNativeCheck;
    private final java.util.concurrent.atomic.AtomicBoolean flightNativeEntered=new java.util.concurrent.atomic.AtomicBoolean();
    private final java.util.Set<String> flightNativeAttemptedRuns=java.util.Collections.synchronizedSet(new java.util.HashSet<String>());
    private static final class ShoppingDispatch {
        final WebRegionNativeBridge bridge;final String run,actionKey,armRaw,armNonce;
        final long armedAt,expiresAt;
        final java.util.concurrent.atomic.AtomicBoolean entered=new java.util.concurrent.atomic.AtomicBoolean();
        volatile long enteredAt=-1;
        volatile HeptaAccessibilityService.NativeRegionCheck liveNative;
        ShoppingDispatch(WebRegionNativeBridge bridge,String run,String actionKey,JSONObject arm)throws Exception{
            this.bridge=bridge;this.run=run;this.actionKey=actionKey;armRaw=WebDomCanonical.canonical(arm);
            armNonce=WebEvidenceJson.text(arm,"request_nonce");armedAt=WebEvidenceJson.number(arm,"armed_elapsed_ms");
            expiresAt=WebEvidenceJson.number(arm,"expires_elapsed_ms");
            need(run.equals(arm.get("model_run_id"))&&bridge.anchorDomPath.equals(arm.get("anchor_dom_path"))
                    &&bridge.bindingSha.equals(arm.get("binding_sha256"))&&bridge.instance.equals(arm.get("webview_instance"))
                    &&bridge.epoch==WebEvidenceJson.number(arm,"navigation_epoch")&&armedAt<expiresAt,
                    "actual ARM is not for the exact native bridge/model run");
        }
    }
    private volatile CityObservationRetry cityObservationRetry;
    private static final class CityObservationRetry {
        final WebFlightDomain before;final String run,nodeId,kind,capabilityPurpose;
        final long dispatchStarted,dispatchEnded;
        private CityObservationRetry(WebFlightDomain before,ActionDecision action,String run,String kind,
                String capabilityPurpose,long start,long end){
            this.before=before;this.run=run;nodeId=action.nodeId;this.kind=kind;this.capabilityPurpose=capabilityPurpose;
            dispatchStarted=start;dispatchEnded=end;
        }
        static CityObservationRetry fromOutcome(WebFlightDomain before,ActionDecision action,String run,
                boolean accepted,boolean dispatched,boolean stale,long start,long end){
            if(before==null||action==null||!accepted||!dispatched||stale||!"click".equals(action.action))return null;
            before.requireCurrent(action);
            String purpose=before.purpose(action.nodeId);
            String kind="choose_departure_city".equals(purpose)?"departure":"choose_arrival_city".equals(purpose)?"arrival":null;
            if(kind==null)return null;
            need(run!=null&&run.matches("[0-9a-f]{32}")&&before.captureEnded>=0&&before.captureEnded<=start&&start<=end,
                    "city-picker retry requires the actual same model dispatch clocks");
            return new CityObservationRetry(before,action,run,kind,purpose,start,end);
        }
        boolean applies(String task,String ownerSha,String authorizationSha,String generation,
                WebEvidenceReceipt first,WebEvidenceReceipt last,PhoneObservation frame,
                boolean stable,WebDomStability.Result domBracket)throws Exception{
            if(stable||domBracket==null||!domBracket.rawEqual||frame==null
                    ||!before.taskId.equals(task)||!before.ownerSha.equals(ownerSha)
                    ||!before.authorizationSha.equals(authorizationSha)||!before.generation.equals(generation)
                    ||!"captured".equals(first.status)||!"captured".equals(last.status)
                    ||!before.bindingSha.equals(first.bindingSha)||!before.bindingSha.equals(last.bindingSha)
                    ||!before.instance.equals(first.instance)||!first.instance.equals(last.instance)
                    ||first.epoch<before.epoch||first.epoch!=last.epoch||!before.url.equals(first.url)||!first.url.equals(last.url)
                    ||first.displayId!=before.displayId||last.displayId!=before.displayId
                    ||first.windowId!=before.windowId||last.windowId!=before.windowId
                    ||first.started<dispatchEnded||first.ended>frame.capturedElapsedMillis||frame.capturedElapsedMillis>last.started
                    ||!WebEvidenceProtocol.HELPER_PACKAGE.equals(frame.packageName)||frame.windowId!=before.windowId
                    ||frame.windowMetadata.displayId==null||frame.windowMetadata.displayId.intValue()!=before.displayId
                    ||!before.generation.equals(frame.backgroundGeneration)||frame.nodesTruncated||frame.collectionStats==null
                    ||frame.collectionStats.truncated()||frame.collectionStats.pending!=0||frame.collectionStats.childSlotsOmitted!=0
                    ||frame.state.imeVisibility!=ImeVisibility.HIDDEN)return false;
            JSONObject binding=first.capture().getJSONObject("binding");
            if(!before.taskId.equals(binding.getString("task_id"))||!before.ownerSha.equals(binding.getString("owner_sha256"))
                    ||!before.contractSha.equals(binding.getString("contract_sha256"))
                    ||!before.authorizationSha.equals(binding.getJSONObject("authorization").getString("authorization_sha256")))return false;
            String raw=first.beforeDomRaw();
            if(!first.stability().rawEqual||!last.stability().rawEqual||!raw.equals(first.domRaw())
                    ||!raw.equals(last.beforeDomRaw())||!raw.equals(last.domRaw()))return false;
            CsairCityPicker a=CsairCityPicker.read(first.dom()),b=CsairCityPicker.read(last.dom());
            return a!=null&&b!=null&&kind.equals(a.kind)&&kind.equals(b.kind);
        }
        JSONObject evidence()throws Exception{
            return new JSONObject().put("schema","hepta.flight-city-picker-observation-retry-source.v1")
                    .put("task_id",before.taskId).put("owner_sha256",before.ownerSha).put("contract_sha256",before.contractSha)
                    .put("authorization_sha256",before.authorizationSha).put("binding_sha256",before.bindingSha)
                    .put("background_generation",before.generation).put("webview_instance",before.instance)
                    .put("source_navigation_epoch",before.epoch).put("display_id",before.displayId).put("window_id",before.windowId)
                    .put("source_observation_id",before.observationId).put("model_run_id",run).put("node_id",nodeId)
                    .put("source_capability_purpose",capabilityPurpose).put("expected_city_picker_kind",kind)
                    .put("dispatch_before_elapsed_ms",dispatchStarted).put("dispatch_after_elapsed_ms",dispatchEnded)
                    .put("accepted",true).put("dispatched",true).put("stale",false)
                    .put("grants_action_capability",false).put("business_verified",false);
        }
    }
    private String loadingDocumentKey;
    private long loadingDocumentStarted,loadingDocumentDeadline;
    private int loadingDocumentReadRetries;
    private static final class PendingNavigation {
        final WebShoppingDomain before;final ActionDecision action;final String run;final long start,end;
        final boolean accepted,dispatched,stale;
        PendingNavigation(WebShoppingDomain before,ActionDecision action,String run,
                          HeptaAccessibilityService.ActionOutcome outcome,long start,long end){
            this.before=before;this.action=action;this.run=run;this.start=start;this.end=end;
            this.accepted=outcome.accepted;this.dispatched=outcome.dispatched;this.stale=outcome.stale;
        }
    }

    static void validateSelection(String owner,BackgroundSession.Selection selection){
        if(selection!=null&&selection.taskTarget!=null){
            selection.requireImmutableTarget(owner);
            if(!selection.taskTarget.webHelper())return; // No helper purpose or session belongs to an explicit native target.
        }
        WebFlightGoal flight=WebFlightGoal.parse(owner);WebShoppingGoal shopping=WebShoppingGoal.parse(owner);
        boolean selected=selection!=null&&selection.allowedPackages.contains(WebEvidenceProtocol.HELPER_PACKAGE);
        if(flight==null&&shopping==null){
            if(selected)throw new IllegalArgumentException("官网查询需要完整的航班日期、城市或支持的商品目标");return;
        }
        if((flight!=null)==(shopping!=null)||selection==null
                ||!WebEvidenceProtocol.HELPER_PACKAGE.equals(selection.initialPackage)
                ||!selection.allowedPackages.equals(Collections.singletonList(WebEvidenceProtocol.HELPER_PACKAGE)))
            throw new IllegalArgumentException("请启用后台模式，并明确选择官网查询工具作为唯一任务应用");
        try{WebTaskPurpose.fromOwner(owner);}
        catch(Exception invalid){throw new IllegalArgumentException("原始指令不允许本次官网只读查询："+invalid.getMessage(),invalid);}
        if(flight!=null&&!flight.departureNotBefore(LocalDate.now()))
            throw new IllegalArgumentException("查询日期已过去，请指定今天或以后的完整日期");
    }
    /** Constructor admission remains helper-only; generic native validation is not Web authority. */
    static void requireWebSelection(String owner,BackgroundSession.Selection selection){
        if(selection!=null&&selection.taskTarget!=null&&!selection.taskTarget.webHelper())
            throw new IllegalArgumentException("所选原生应用不能创建网页任务");
        validateSelection(owner,selection);
    }
    static boolean supported(String owner){return WebFlightGoal.parse(owner)!=null||WebShoppingGoal.parse(owner)!=null;}
    static boolean hasUnreleased(Context context){return WebEvidenceJournal.hasUnreleased(context);}

    WebFlightSession(HeptaAccessibilityService service,String task,String owner,TaskAuthorization.Gate authorization,
                     BackgroundSession background,QualificationScopeConfig.FilesRoot filesRoot,File evidence,
                     TaskCompletionGate completion,HeptaAccessibilityService.Cancellation cancellation)throws Exception{
        requireWebSelection(owner,background==null?null:background.selection);
        purpose=WebTaskPurpose.fromOwner(owner);goal=purpose.flight;
        need(task.equals(authorization.taskId)&&completion!=null,"same task public-page contract required");
        authorization.authorization.requireOwner(owner);authorization.ready();
        if(background!=null&&background.selection.taskTarget!=null)
            background.selection.requireTaskTarget(owner,authorization.authorization);
        need(WebEvidenceBinding.canonical(new JSONObject(purpose.authorization.evidence())).equals(
                WebEvidenceBinding.canonical(new JSONObject(authorization.authorization.evidence()))),
                "actual complete original OWNER authorization differs");
        this.service=service;this.taskId=task;this.authorization=authorization;this.background=background;
        this.cancellation=cancellation;this.completion=completion;this.evidence=evidence;
        background.requireActive();need(background.ownerSha256.equals(purpose.ownerSha256),"background OWNER differs");
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
                .put("owner",owner).put("owner_sha256",purpose.ownerSha256).put("contract_sha256",purpose.contractSha256)
                .put("authorization",new JSONObject(authorization.authorization.evidence()))
                .put("background",bg).put("controller_identity",controller.evidence).put("helper_identity",helper.evidence);
        JSONObject binding=WebEvidenceBinding.fromAttach(attach);
        immutableBinding=new JSONObject(WebEvidenceBinding.canonical(binding));
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
        JSONObject ownerEvidence=goal!=null?new JSONObject(goal.evidence()):
                new JSONObject(purpose.shopping.canonicalContract()).put("original_owner",purpose.owner);
        record("web-flight-owner.json",ownerEvidence.put("task_id",task)
                .put("goal_kind",purpose.kind).put("site_policy",purpose.policyEvidence())
                .put("site_policy_sha256",purpose.sitePolicySha256).put("initial_url",purpose.initialUrl)
                .put("bootstrap_is_model_query",false)
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
        CityObservationRetry observationRetry=cityObservationRetry;cityObservationRetry=null;
        PhoneObservation before=initial;long captureDeadline=deadline;String loadingAttemptKey=null;
        while(true){
        HeptaAccessibilityService.FlightObservationSnapshot nativeSource=null;
        try{
        service.requireBackgroundObservation(taskId,before);
        if(goal!=null||purpose.shopping!=null)nativeSource=service.retainFlightObservation(this,before,cancellation,captureDeadline);
        WebEvidenceReceipt first=client.capture(captureDeadline);
        if("state_changed".equals(first.status)&&"private evidence storage budget reached".equals(first.callback().opt("reason")))
            return publishWaiting(before,first,"initial_capture_storage_exhausted");
        if("state_changed".equals(first.status)){
            // At most one read-only retry, after a fresh AX window observation; never repeat an action.
            if(nativeSource!=null){nativeSource.close();nativeSource=null;}
            before=observer.observe();service.requireBackgroundObservation(taskId,before);
            if(goal!=null||purpose.shopping!=null)nativeSource=service.retainFlightObservation(this,before,cancellation,captureDeadline);
            first=client.capture(captureDeadline);
            need("captured".equals(first.status)||"unavailable".equals(first.status)||"state_changed".equals(first.status),
                    "unknown reply after the single evidence retry");
        }
        if("unavailable".equals(first.status)||"state_changed".equals(first.status)){
            PhoneObservation after=observer.observe();service.requireBackgroundObservation(taskId,after);
            return publishWaiting(after,first,"initial_capture_not_stable");
        }
        need("captured".equals(first.status),"actual page capture unavailable");
        PhoneObservation after=observer.observe();service.requireBackgroundObservation(taskId,after);
        WebEvidenceReceipt last=client.capture(captureDeadline);
        if("unavailable".equals(last.status)||"state_changed".equals(last.status))
            return publishWaiting(after,last,"final_capture_not_stable");
        need("captured".equals(last.status),"actual final page capture unavailable");
        String actualLoadingKey=loadingKey(last);
        need(loadingAttemptKey==null||loadingAttemptKey.equals(actualLoadingKey),
                "read-only loading retry changed the original instance, URL or navigation epoch");
        WebDomStability.Result domBracket=null;
        try{
            domBracket=WebDomStability.evaluate(first.domRaw(),last.beforeDomRaw(),purpose.sitePolicyId);
        }catch(Exception incompleteBracket){
            // A changing bracket supplies no action. Existing loading retries
            // remain bounded and read-only; no preceding click is repeated.
        }
        boolean sameOriginalFrame=sameFrame(before,after);
        boolean sameCaptureIdentity=first.instance.equals(last.instance)&&first.epoch==last.epoch
                &&first.url.equals(last.url)&&first.bindingSha.equals(last.bindingSha)
                &&first.displayId==last.displayId&&first.windowId==last.windowId;
        boolean sameCaptureDomain=sameCaptureIdentity&&domBracket!=null;
        boolean stable=sameOriginalFrame&&sameCaptureDomain;
        JSONObject nativeObservationBracket=null;
        if(sameCaptureIdentity&&purpose.shopping!=null&&nativeSource!=null
                &&WebShoppingObservationStability.supportsCaptures(first.capture(),last.capture())){
            // A private complete native proof admits only this new card observation.
            // It creates no product ARM; beforeModelAction and native dispatch retain every original gate.
            nativeObservationBracket=service.verifyFlightObservationBracket(this,nativeSource,after,first,last,
                    cancellation,captureDeadline);
            stable=true;
        }
        if(retryLoadingDocument(first,last,after,stable,domBracket,observationRetry,captureDeadline)){
            loadingAttemptKey=actualLoadingKey;
            captureDeadline=Math.min(captureDeadline,loadingDocumentDeadline);
            before=observer.observe();service.requireBackgroundObservation(taskId,before);
            continue;
        }
        if(!stable&&sameCaptureIdentity&&goal!=null&&nativeSource!=null
                &&first.stability().rawEqual&&last.stability().rawEqual){
            // This service-created proof only admits the new read-only frame.
            // It independently replays the complete homepage DOM scope and all
            // native guards even when the shared generic DOM bracket rejected it.
            // A later action still needs its own original model target and live Permit checks.
            nativeObservationBracket=service.verifyFlightObservationBracket(this,nativeSource,after,first,last,
                    cancellation,captureDeadline);
            stable=true;
        }
        need(stable,"AX/DOM bracket changed; no current page capability published");
        WebNativeGeometry firstGeometry=WebNativeGeometry.read(first.capture(),first.dom(),first.displayId,first.windowId,first.stability());
        WebNativeGeometry lastGeometry=WebNativeGeometry.read(last.capture(),last.dom(),last.displayId,last.windowId,last.stability());
        need(firstGeometry==null&&lastGeometry==null||firstGeometry!=null&&firstGeometry.same(lastGeometry),
                "native WebView geometry changed across the AX/DOM bracket");
        WebTaskDomain observed=applyNavigation(WebTaskDomain.observed(taskId,purpose,authorization,after,last,immutableBinding));
        if(observed.shopping!=null&&nativeObservationBracket!=null)
            observed=observed.withShoppingReadQuote(purpose.shopping,after,last,nativeObservationBracket);
        record("web-frame-"+after.id+".json",new JSONObject(observed.evidence())
                .put("first_capture_request_nonce",first.callback().getString("request_nonce"))
                .put("last_capture_request_nonce",last.callback().getString("request_nonce"))
                .put("first_ax_observation_id",before.id).put("last_ax_observation_id",after.id)
                .put("ax_dom_capture_is_atomic",false)
                .put("original_same_frame_predicate",sameOriginalFrame)
                .put("readonly_native_observation_bracket",nativeObservationBracket==null?JSONObject.NULL:nativeObservationBracket)
                .put("readonly_native_observation_proof_grants_action",false)
                .put("same_lease_epoch_and_equal_dom_bracket",first.stability().rawEqual&&domBracket!=null&&domBracket.rawEqual&&last.stability().rawEqual)
                .put("same_lease_epoch_and_stable_dom_scope_bracket",true)
                .put("between_captures_dom_stability",domBracket==null?JSONObject.NULL:domBracket.evidence())
                .put("first_capture_dom_stability_sha256",WebDomCanonical.sha256(first.stability().evidence()))
                .put("last_capture_dom_stability_sha256",WebDomCanonical.sha256(last.stability().evidence()))
                .put("same_native_geometry_bracket",firstGeometry!=null)
                .put("native_geometry_sha256",lastGeometry==null?JSONObject.NULL:lastGeometry.fingerprint));
        current=after;currentCapture=last;domain=observed;completion.bindWebDomain(observed);
        flightNativePermit=null;flightNativeCheck=null;
        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;
        return after;
        }finally{if(nativeSource!=null)nativeSource.close();}
        }
    }
    private static String loadingKey(WebEvidenceReceipt receipt){
        return receipt.bindingSha+"\n"+receipt.instance+"\n"+receipt.epoch+"\n"+receipt.url
                +"\n"+receipt.displayId+"\n"+receipt.windowId;
    }
    /** Extra observations are bounded and read-only; an entry click is never replayed. */
    private boolean retryLoadingDocument(WebEvidenceReceipt first,WebEvidenceReceipt last,PhoneObservation frame,
                                         boolean stable,WebDomStability.Result domBracket,CityObservationRetry observationRetry,long deadline)throws Exception{
        boolean shoppingUnstable=goal==null&&purpose.shopping!=null&&!stable;
        if(goal==null&&!shoppingUnstable)return false;
        String key=loadingKey(last);
        CsairCalendar a=goal==null?null:CsairCalendar.read(first.dom()),b=goal==null?null:CsairCalendar.read(last.dom());
        boolean bodyPending=a!=null&&a.headerOnly||b!=null&&b.headerOnly;
        boolean bookingPending=goal!=null&&(WebFlightDomain.bookingBodyPending(first.dom())||WebFlightDomain.bookingBodyPending(last.dom()));
        boolean queryPending=flightProgress!=null&&flightProgress.queryDispatched();
        boolean cityPickerTransition=observationRetry!=null&&!nativeQueryEntered.get()
                &&(flightProgress==null||!flightProgress.queryAttempted())
                &&observationRetry.applies(taskId,purpose.ownerSha256,authorization.authorization.sha256,background.generation,
                        first,last,frame,stable,domBracket);
        // A city-open credential never inherits the generic loading-key continuation:
        // every new city retry must replay its own exact picker/four-DOM predicates.
        if(!shoppingUnstable&&!bodyPending&&!bookingPending&&!queryPending&&!cityPickerTransition
                &&!(observationRetry==null&&key.equals(loadingDocumentKey)&&!stable))return false;
        need(first.instance.equals(last.instance)&&first.epoch==last.epoch&&first.url.equals(last.url)
                &&first.bindingSha.equals(last.bindingSha)&&first.displayId==last.displayId
                &&first.windowId==last.windowId,"loading observation changed the immutable page domain");
        long now=SystemClock.elapsedRealtime();
        if(!key.equals(loadingDocumentKey)){
            loadingDocumentKey=key;loadingDocumentStarted=now;loadingDocumentReadRetries=0;
            // The actual city failure cost about 6.8s per full extra AX/DOM bracket.
            // Actual MI capture plus verified reply costs about 4.5s; two full extra reads need a 32s phase.
            // Freeze one phase deadline; no retry extends it or the original task deadline.
            loadingDocumentDeadline=Math.min(deadline,now+(shoppingUnstable?32000:cityPickerTransition?16000:6000));
        }
        if(loadingDocumentReadRetries>=2||now+250>=Math.min(deadline,loadingDocumentDeadline))return false;
        need(!retired&&!cancellation.isCancelled(),"web task retired while waiting for page content");
        service.requireTaskAuthorization(taskId,authorization);background.requireActive();
        loadingDocumentReadRetries++;
        record("web-load-wait-"+UUID.randomUUID().toString().replace("-","")+".json",new JSONObject()
                .put("schema","hepta.web-read-only-content-wait.v1").put("task_id",taskId)
                .put("binding_sha256",journal.bindingSha).put("webview_instance",last.instance)
                .put("navigation_epoch",last.epoch).put("native_url",last.url)
                .put("observation_id",frame.id).put("first_request_nonce",first.callback().getString("request_nonce"))
                .put("last_request_nonce",last.callback().getString("request_nonce"))
                .put("first_dom_sha256",first.domSha).put("last_dom_sha256",last.domSha)
                .put("recognized_calendar_body_pending",bodyPending).put("recognized_booking_body_pending",bookingPending)
                .put("shopping_unstable_readonly_bracket",shoppingUnstable)
                .put("actual_query_awaiting_results",queryPending)
                .put("actual_city_picker_transition",cityPickerTransition?observationRetry.evidence():JSONObject.NULL)
                .put("read_only_retry",loadingDocumentReadRetries)
                .put("maximum_extra_reobservations",2).put("deadline_elapsed_ms",Math.min(deadline,loadingDocumentDeadline))
                .put("action_replayed",false).put("model_action_dispatched",false).put("business_verified",false));
        SystemClock.sleep(200);
        need(!retired&&!cancellation.isCancelled(),"web task retired while waiting for page content");
        need(SystemClock.elapsedRealtime()<Math.min(deadline,loadingDocumentDeadline),
                "read-only content wait exceeded its original deadline");
        service.requireTaskAuthorization(taskId,authorization);background.requireActive();
        return true;
    }
    private PhoneObservation publishWaiting(PhoneObservation frame,WebEvidenceReceipt receipt,String reason)throws Exception{
        shoppingReadCompletion=null;
        JSONObject callback=receipt.callback();
        if(("unavailable".equals(receipt.status)||"state_changed".equals(receipt.status))
                &&"private evidence storage budget reached".equals(callback.opt("reason"))){
            // This authenticated helper refusal cannot recover by waiting for the page.
            // Preserve it and leave through the ordinary task failure/cleanup path.
            record("web-capture-fatal-"+callback.getString("request_nonce")+".json",new JSONObject()
                    .put("schema","hepta.web-permanent-capture-failure.v1").put("task_id",taskId)
                    .put("observation_id",frame.id).put("capture_callback",callback)
                    .put("reason","private_evidence_storage_exhausted").put("automatic_retry",false)
                    .put("model_wait_requested",false).put("business_verified",false));
            throw new IllegalStateException("网页证据存储已达上限，本次任务已停止；证据归档完成后才能继续查询");
        }
        WebTaskDomain waiting=applyNavigation(WebTaskDomain.waiting(taskId,purpose,authorization,frame,receipt,immutableBinding));
        record("web-frame-"+frame.id+".json",new JSONObject(waiting.evidence()).put("reason",reason)
                .put("capture_metadata_only",true).put("ax_dom_capture_is_atomic",false)
                .put("same_lease_epoch_and_equal_dom_bracket",false));
        current=frame;currentCapture=null;domain=waiting;completion.bindWebDomain(waiting);
        flightNativePermit=null;flightNativeCheck=null;
        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;return frame;
    }
    void beforeModelAction(ActionDecision action,String run,long deadline)throws Exception{
        cityObservationRetry=null;shoppingReadCompletion=null;
        boolean prepared=false;
        try{
        WebTaskDomain original=domain;PhoneObservation frame=current;
        need(original!=null&&frame!=null&&run!=null&&run.matches("[0-9a-f]{32}"),"current model-bound web action required");
        original.requireCurrent(action);service.requireTaskAuthorization(taskId,authorization);background.requireActive();
        dispatchSource=null;dispatchSourceRun=null;dispatchSourceAction=null;
        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;shoppingDispatch=null;
        flightNativePermit=null;flightNativeCheck=null;flightNativeEntered.set(false);
        if("wait".equals(action.action)||"done".equals(action.action)&&!"success".equals(action.status)){
            // These choices do not manipulate a page. A missing capture never
            // becomes click/type/success authority and never clears the journal.
            dispatchSource=original;dispatchSourceRun=run;dispatchSourceAction=actionKey(action);
            dispatchCheckedRun=run;dispatchCheckedAction=actionKey(action);
            dispatchCheckedAt=SystemClock.elapsedRealtime();
            record("web-dispatch-"+run+".json",new JSONObject(original.evidence()).put("model_run_id",run)
                    .put("model_issued",true).put("action",action.action).put("no_page_effect",true)
                    .put("dispatched",false).put("source","current_restricted_model_choice"));
            prepared=true;return;
        }
        WebEvidenceReceipt fresh=client.capture(deadline);
        need("captured".equals(fresh.status),"document changed before action");
        WebTaskDomain rechecked=applyNavigation(WebTaskDomain.observed(taskId,purpose,authorization,frame,fresh,immutableBinding));
        if(original.shopping!=null&&original.shopping.searchQuote!=null)
            rechecked=rechecked.withRecheckedShoppingQuote(original.shopping.searchQuote,frame,fresh);
        need(original.instance.equals(rechecked.instance)&&original.epoch==rechecked.epoch
                &&original.pageKey.equals(rechecked.pageKey)&&original.clickIds.equals(rechecked.clickIds)
                &&original.editValues.equals(rechecked.editValues),"page target changed since model observation");
        rechecked.requireCurrent(action);
        flightNativePermit=WebFlightNativeStability.prepare(rechecked,frame,action,run,currentCapture,fresh);
        if(flightNativePermit!=null)need(!flightNativeAttemptedRuns.contains(run)&&flightNativeAttemptedRuns.size()<64,
                "booking invocation for this model run is already consumed or its bounded attempt budget is full");
        if(rechecked.shopping!=null&&"click".equals(action.action)){
            need(pendingNavigation==null,"a prior product navigation is still unknown; no new click or ARM");
            WebRegionNativeBridge bridge=WebRegionNativeBridge.bind(frame,fresh);
            need(bridge!=null&&bridge.anchor.id.equals(action.nodeId)
                    &&bridge.anchorDomPath.equals(rechecked.shopping.observedLinkAnchorPath(action)),
                    "fresh same-frame native product region changed");
            bridge.requireFrame(frame);
            WebEvidenceReceipt armed=client.armObservedLink(fresh,bridge.anchorDomPath,run,deadline);
            JSONObject actualArm=armed.arm();
            rechecked=rechecked.withObservedLinkArm(actualArm);
            ShoppingDispatch pending=new ShoppingDispatch(bridge,run,actionKey(action),actualArm);
            record("web-observed-link-arm-"+run+".json",new JSONObject().put("schema","hepta.controller-observed-link-arm.v1")
                    .put("task_id",taskId).put("binding_sha256",journal.bindingSha).put("model_run_id",run)
                    .put("source_capture_request_nonce",fresh.callback().getString("request_nonce"))
                    .put("actual_arm",actualArm).put("actual_callback",armed.callback())
                    .put("native_region_bridge",bridge.evidence()).put("native_invocation_entered",false)
                    .put("automatic_retry",false).put("business_verified",false));
            // Only the exact successful ARM is retained. Both Client and helper
            // keep attempt fences across later captures, failures and timeouts.
            shoppingDispatch=pending;
        }
        if(rechecked.flight!=null&&WebFlightProgress.QUERY.equals(rechecked.flight.purpose(action.nodeId))){
            need(flightProgress!=null&&!nativeQueryEntered.get(),"one query attempt per original lease");
            flightProgress=flightProgress.reserveQuery(rechecked.flight,action,run);
            record("web-query-reservation-"+run+".json",new JSONObject(flightProgress.evidence(rechecked.flight))
                    .put("source","durable_before_native_invocation").put("dispatch_attempted",false));
        }
        dispatchSource=rechecked;dispatchSourceRun=run;dispatchSourceAction=actionKey(action);
        dispatchCheckedRun=run;dispatchCheckedAction=actionKey(action);
        dispatchCheckedAt=SystemClock.elapsedRealtime();
        record("web-dispatch-"+run+".json",new JSONObject(rechecked.evidence())
                .put("model_run_id",run).put("model_issued",true).put("action",action.action)
                .put("node_id",action.nodeId==null?JSONObject.NULL:action.nodeId)
                .put("original_dom_sha256",original.evidence().get("dom_sha256"))
                .put("fresh_capture_request_nonce",fresh.callback().getString("request_nonce"))
                .put("unchanged_semantic_region",true).put("whole_dom_equality_claimed",false)
                .put("flight_home_native_stability_scope",flightNativePermit==null?JSONObject.NULL:flightNativePermit.domEvidence())
                .put("dispatched",false).put("source","pre_dispatch_read_only_check_not_action_outcome"));
        prepared=true;
        }finally{
            // A failed guard, fresh read, ARM or durable record never leaves a
            // dispatch capability. The Client/helper attempt fences remain consumed.
            if(!prepared){
                dispatchSource=null;dispatchSourceRun=null;dispatchSourceAction=null;
                dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;shoppingDispatch=null;
                flightNativePermit=null;flightNativeCheck=null;
            }
        }
    }
    void requireDispatch(ActionDecision action,String run){
        WebTaskDomain d=domain;need(!retired&&d!=null&&run!=null&&run.equals(dispatchCheckedRun)
                &&(action.action+"\n"+(action.nodeId==null?"":action.nodeId)).equals(dispatchCheckedAction)
                &&SystemClock.elapsedRealtime()>=dispatchCheckedAt&&SystemClock.elapsedRealtime()-dispatchCheckedAt<=1500,
                "fresh exact web/model action evidence expired");
        d.requireCurrent(action);
    }
    WebFlightNativeStability.Permit flightNativePermitForDispatch(ActionDecision action,PhoneObservation frame){
        WebFlightNativeStability.Permit permit=flightNativePermit;
        if(permit==null)return null;
        requireDispatch(action,dispatchCheckedRun);
        need(!cancellation.isCancelled()&&permit.matches(frame,action,dispatchCheckedRun)
                &&frame==current&&!flightNativeEntered.get(),"exact unconsumed homepage booking dispatch required");
        return permit;
    }
    void acceptFlightNativeCheck(ActionDecision action,PhoneObservation frame,HeptaAccessibilityService.FlightNativeCheck check)throws Exception{
        WebFlightNativeStability.Permit permit=flightNativePermitForDispatch(action,frame);
        need(permit!=null&&check!=null&&check.matches(frame,permit)&&flightNativeCheck==null,
                "one actual native homepage check required");
        // Preserve the complete actual source/fresh snapshots and their exact
        // differences before the platform call. This record grants no input API.
        record("web-flight-native-stability-"+permit.run+".json",check.evidence());
        flightNativeCheck=check;
    }
    WebRegionNativeBridge nativeRegionForDispatch(ActionDecision action,String run,PhoneObservation frame){
        WebTaskDomain value=domain;
        if(value==null||value.shopping==null||!"click".equals(action.action))return null;
        requireDispatch(action,run);
        ShoppingDispatch actual=requireShoppingDispatch(action,run);
        need(frame==current,"native region must use the controller's exact current frame");
        actual.bridge.requireFrame(frame);return actual.bridge;
    }
    void acceptNativeRegionCheck(ActionDecision action,String run,HeptaAccessibilityService.NativeRegionCheck actual){
        ShoppingDispatch attempt=requireShoppingDispatch(action,run);
        need(actual!=null&&actual.matches(current,attempt.bridge)
                &&actual.checkedAt>=attempt.armedAt&&actual.checkedAt<attempt.expiresAt
                &&attempt.liveNative==null&&!attempt.entered.get(),
                "live native region check is absent, duplicated or belongs to another ARM");
        attempt.liveNative=actual;
    }
    private ShoppingDispatch requireShoppingDispatch(ActionDecision action,String run){
        ShoppingDispatch actual=shoppingDispatch;WebTaskDomain source=dispatchSource;
        long now=SystemClock.elapsedRealtime();
        need(!retired&&!cancellation.isCancelled()&&source!=null&&source.shopping!=null&&actual!=null
                &&run!=null&&run.equals(dispatchSourceRun)&&run.equals(actual.run)
                &&actionKey(action).equals(dispatchSourceAction)&&actionKey(action).equals(actual.actionKey)
                &&actual.bridge.anchor.id.equals(action.nodeId)&&actual.armedAt<=now&&now<actual.expiresAt,
                "fresh exact one-shot product ARM is missing or expired");
        return actual;
    }
    /** Called once immediately before the original ACTION_CLICK platform call,
     * after the service's repeated authority/window/signature checks. No I/O. */
    void beforeNativeClickInvocation(ActionDecision action,String run){
        WebTaskDomain source=dispatchSource,currentDomain=domain;
        WebFlightNativeStability.Permit permit=flightNativePermit;
        if(permit!=null){
            requireDispatch(action,run);
            HeptaAccessibilityService.FlightNativeCheck check=flightNativeCheck;long now=SystemClock.elapsedRealtime();
            need(permit.matches(current,action,run)&&check!=null&&check.matches(current,permit)
                    &&check.checkedAt<=now&&now-check.checkedAt<=250
                    &&flightNativeEntered.compareAndSet(false,true)&&flightNativeAttemptedRuns.add(run),
                    "booking native check expired, mismatched or already consumed");
        }
        if(purpose.shopping!=null&&"click".equals(action.action)){
            ShoppingDispatch actual=requireShoppingDispatch(action,run);
            HeptaAccessibilityService.NativeRegionCheck live=actual.liveNative;
            actual.bridge.requireFrame(current);
            long now=SystemClock.elapsedRealtime();
            need(live!=null&&live.matches(current,actual.bridge)&&live.checkedAt<=now&&now-live.checkedAt<=250
                    &&actual.entered.compareAndSet(false,true),
                    "product native invocation lacks its actual fresh region/window check or was already entered");
            actual.enteredAt=now;return;
        }
        boolean queryTarget=currentDomain!=null&&currentDomain.flight!=null
                &&WebFlightProgress.QUERY.equals(currentDomain.flight.purpose(action.nodeId));
        boolean reserved=flightProgress!=null&&flightProgress.isQueryAction(action,run);
        if(!queryTarget&&!reserved)return;
        need(source!=null&&source.flight!=null&&flightProgress!=null
                &&run!=null&&run.equals(dispatchSourceRun)&&actionKey(action).equals(dispatchSourceAction)
                &&flightProgress.reservedFor(source.flight,action,run)
                &&nativeQueryEntered.compareAndSet(false,true),
                "public query native invocation is missing, mismatched or already consumed");
    }
    private static String actionKey(ActionDecision action){return action.action+"\n"+(action.nodeId==null?"":action.nodeId);}
    /** Called with the original executor Outcome, immediately after the actual awaited dispatch. */
    void modelActionOutcome(ActionDecision action,String run,HeptaAccessibilityService.ActionOutcome outcome,
                            long dispatchStarted,long dispatchEnded)throws Exception{
        cityObservationRetry=null;shoppingReadCompletion=null;
        WebTaskDomain before=dispatchSource;
        try{
        need(!retired&&before!=null&&outcome!=null&&run!=null&&run.equals(dispatchSourceRun)
                &&actionKey(action).equals(dispatchSourceAction)&&action.observationId.equals(before.observationId)
                &&dispatchCheckedAt<=dispatchStarted&&dispatchStarted<=dispatchEnded
                &&dispatchEnded<=SystemClock.elapsedRealtime(),"actual same model action and dispatch clocks required");
        record("web-action-"+run+".json",new JSONObject(before.evidence()).put("model_run_id",run)
                .put("action",action.action).put("node_id",action.nodeId==null?JSONObject.NULL:action.nodeId)
                .put("dispatch_before_elapsed_ms",dispatchStarted).put("dispatch_after_elapsed_ms",dispatchEnded)
                .put("accepted",outcome.accepted).put("dispatched",outcome.dispatched).put("stale",outcome.stale)
                .put("source","actual_controller_executor_outcome").put("model_issued",true).put("business_verified",false));
        if(before.shopping!=null&&"done".equals(action.action)&&"success".equals(action.status)){
            WebShoppingQuote.Pending pending=WebShoppingQuote.Pending.fromOutcome(completion,before,action,run,
                    outcome.accepted,outcome.dispatched,outcome.stale,dispatchStarted,dispatchEnded);
            if(pending!=null){
                record("web-shopping-read-done-source-"+run+".json",pending.evidence());
                shoppingReadCompletion=pending;
            }
        }
        if(before.flight!=null&&"click".equals(action.action)){
            need(flightProgress!=null,"actual flight progression missing");
            flightProgress=flightProgress.outcome(before.flight,action,run,outcome.accepted,outcome.dispatched,
                    outcome.stale,nativeQueryEntered.get(),dispatchStarted,dispatchEnded);
            record("web-flight-progress-"+run+".json",new JSONObject(flightProgress.evidence(before.flight))
                    .put("source","actual_controller_executor_outcome"));
            CityObservationRetry transition=CityObservationRetry.fromOutcome(before.flight,action,run,
                    outcome.accepted,outcome.dispatched,outcome.stale,dispatchStarted,dispatchEnded);
            if(transition!=null){
                record("web-city-observation-source-"+run+".json",transition.evidence());cityObservationRetry=transition;
            }
        }
        if(before.shopping!=null&&"click".equals(action.action)){
            ShoppingDispatch actual=shoppingDispatch;
            need(actual!=null&&actual.run.equals(run)&&actual.actionKey.equals(actionKey(action)),
                    "actual product ARM dispatch record missing");
            record("web-observed-link-native-"+run+".json",new JSONObject().put("schema","hepta.controller-observed-link-native.v1")
                    .put("task_id",taskId).put("binding_sha256",journal.bindingSha).put("model_run_id",run)
                    .put("actual_arm",new JSONObject(actual.armRaw)).put("native_invocation_entered",actual.entered.get())
                    .put("native_entered_elapsed_ms",actual.enteredAt<0?JSONObject.NULL:actual.enteredAt)
                    .put("native_region_check",actual.liveNative==null?JSONObject.NULL:actual.liveNative.evidence())
                    .put("dispatch_before_elapsed_ms",dispatchStarted).put("dispatch_after_elapsed_ms",dispatchEnded)
                    .put("accepted",outcome.accepted).put("dispatched",outcome.dispatched).put("stale",outcome.stale)
                    .put("automatic_retry",false).put("business_verified",false));
            if(outcome.accepted&&outcome.dispatched&&!outcome.stale){
                need(actual.entered.get()&&actual.liveNative!=null
                        &&dispatchStarted<=actual.enteredAt&&actual.enteredAt<=dispatchEnded
                        &&actual.enteredAt<actual.expiresAt,"native product click was not observed within its ARM");
                need(pendingNavigation==null,"a prior actual product navigation is still unconfirmed");
                pendingNavigation=new PendingNavigation(before.shopping,action,run,outcome,dispatchStarted,dispatchEnded);
            }
        }
        }finally{
            dispatchSource=null;dispatchSourceRun=null;dispatchSourceAction=null;
            dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;shoppingDispatch=null;
            flightNativePermit=null;flightNativeCheck=null;
        }
    }
    WebShoppingQuote.Completion shoppingCompletion(ActionDecision action,String run,PhoneObservation before,PhoneObservation after,long deadline)throws Exception{
        WebShoppingQuote.Pending pending=shoppingReadCompletion;shoppingReadCompletion=null;
        if(pending==null)return null;
        need(!retired&&!cancellation.isCancelled()&&SystemClock.elapsedRealtime()<deadline&&current==after&&domain!=null,"current final read is unavailable");
        service.requireTaskAuthorization(taskId,authorization);background.requireActive();
        WebShoppingQuote.Completion proof=pending.complete(completion,domain,action,run,before,after);
        need(!retired&&!cancellation.isCancelled()&&SystemClock.elapsedRealtime()<deadline&&current==after&&domain!=null,"final quote read retired or timed out");
        service.requireTaskAuthorization(taskId,authorization);background.requireActive();
        record("web-shopping-final-read-"+run+".json",proof.evidence());
        need(!retired&&!cancellation.isCancelled()&&SystemClock.elapsedRealtime()<deadline&&current==after&&domain!=null,"persisted final quote read retired or timed out");
        service.requireTaskAuthorization(taskId,authorization);background.requireActive();return proof;
    }
    private WebTaskDomain applyNavigation(WebTaskDomain value)throws Exception{
        if(value.flight!=null){
            if(flightProgress==null)flightProgress=WebFlightProgress.begin(value.flight);
            flightProgress=flightProgress.observed(value.flight);
            return value.withFlightProgress(flightProgress);
        }
        if(value.shopping==null)return value;
        if(shoppingNavigation!=null&&!shoppingNavigation.matches(value.shopping))shoppingNavigation=null;
        if(pendingNavigation!=null&&"official_product_detail".equals(value.phase)){
            PendingNavigation actual=pendingNavigation;
            shoppingNavigation=WebShoppingDomain.Navigation.confirm(actual.before,value.shopping,actual.action,
                    actual.run,actual.accepted,actual.dispatched,actual.stale,actual.start,actual.end);
            record("web-navigation-"+actual.run+".json",new JSONObject(shoppingNavigation.evidence()));
            pendingNavigation=null;
        }
        return shoppingNavigation!=null?value.withNavigation(shoppingNavigation):value;
    }
    boolean released(){return retired&&cleanupKnown;}
    synchronized void acceptReconciliation(Cleanup proof)throws Exception{
        need(proof!=null&&proof.known&&retired&&Boolean.TRUE.equals(proof.evidence.get("cleanup_known"))
                &&taskId.equals(proof.evidence.getString("task_id"))
                &&journal.bindingSha.equals(proof.evidence.getString("binding_sha256"))
                &&!hasUnreleased(service),"helper retirement proof does not match this original task");
        cleanupKnown=true;
    }
    void serviceRetired(){retired=true;cityObservationRetry=null;shoppingReadCompletion=null;if(flightProgress!=null)flightProgress.retire();domain=null;currentCapture=null;flightNativePermit=null;flightNativeCheck=null;pendingNavigation=null;shoppingNavigation=null;dispatchSource=null;shoppingDispatch=null;
        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;client.close();}
    Cleanup close(String reason){
        TaskCompletionGate.WebCloseAttempt completionClose=completion.beginWebClose(this,domain,taskId,journal.bindingSha,reason);
        boolean closeReturnedNormally=false;
        retired=true;cityObservationRetry=null;shoppingReadCompletion=null;if(flightProgress!=null)flightProgress.retire();domain=null;currentCapture=null;flightNativePermit=null;flightNativeCheck=null;pendingNavigation=null;shoppingNavigation=null;dispatchSource=null;shoppingDispatch=null;
        dispatchCheckedRun=null;dispatchCheckedAction=null;dispatchCheckedAt=0;completion.clearWebDomain();
        try{
            if(!journal.attachWasPrepared()){
                journal.closeNeverAttached();cleanupKnown=true;
                return new Cleanup(true,new JSONObject().put("cleanup_known",true).put("no_attach_request_prepared",true)
                        .put("task_id",taskId).put("binding_sha256",journal.bindingSha));
            }
            WebEvidenceReceipt proof=client.closeLease(reason,SystemClock.elapsedRealtime()+10000);
            journal.closeKnown(proof);cleanupKnown=true;
            JSONObject actualCallback=proof.callback();
            Cleanup known=new Cleanup(true,new JSONObject().put("cleanup_known",true).put("helper",actualCallback)
                    .put("task_id",taskId).put("binding_sha256",journal.bindingSha).put("business_verified",false));
            if(proof.cleanupKnown&&!proof.recovered&&!proof.unstarted)
                completion.webCloseKnown(completionClose,this,actualCallback.getString("task_id"),proof.bindingSha,
                        proof.status,proof.instance,proof.epoch,proof.displayId,proof.windowId,
                        WebEvidenceJson.sha(WebDomCanonical.canonical(actualCallback)));
            else completion.abortWebClose(completionClose);
            closeReturnedNormally=true;return known;
        }catch(Exception unknown){
            try{return new Cleanup(false,new JSONObject().put("cleanup_known",false).put("task_id",taskId)
                    .put("binding_sha256",journal.bindingSha).put("error",HeptaAccessibilityService.limited(HeptaAccessibilityService.message(unknown),512))
                    .put("automatic_retry",false));}catch(Exception impossible){throw new IllegalStateException(impossible);}
        }finally{
            if(!closeReturnedNormally)completion.abortWebClose(completionClose);
            client.close();
        }
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
