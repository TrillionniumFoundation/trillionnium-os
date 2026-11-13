package org.trillionnium.hepta.webhelper;

import android.content.Context;
import android.hardware.display.DisplayManager;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;
import org.json.JSONObject;
import org.json.JSONArray;
import org.trillionnium.hepta.webprotocol.WebRecoveryPolicy;
import org.trillionnium.hepta.webprotocol.WebStorageEvidence;
import java.nio.charset.StandardCharsets;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** One owned page/lease. Every mutation is serialized on the helper UI thread. */
final class EvidenceSession {
    private static EvidenceSession singleton;
    static synchronized EvidenceSession get(Context context)throws Exception{
        if(singleton==null)singleton=new EvidenceSession(context.getApplicationContext());return singleton;
    }
    private final Context context;
    private final Handler ui=new Handler(Looper.getMainLooper());
    private final ExecutorService fileWriter=Executors.newSingleThreadExecutor();
    final EvidenceFiles files;
    private PageActivity page;
    private TaskBinding binding;
    private JSONObject previous;
    private byte[] previousRaw;
    private EvidenceFiles.Record preservedPrevious,recoveredRecord,unstartedRecord;
    private String attachRequestRaw;
    private long attachBoundElapsed;
    private JSONObject recoveredVerdict,displayBefore;
    private final ProcessIdentity processIdentity;
    private PageActivity retiringPage;
    private RemoteReply pendingAttach,pendingClose,recoveryReply;
    private boolean storagePending,recoveryInProgress,manualCleanupPending;
    private final LinkedHashMap<String,JSONObject> closeUsed=new LinkedHashMap<String,JSONObject>();
    private final java.util.TreeSet<String> closeHistory=new java.util.TreeSet<String>();
    private boolean orphan,retired,firstCaptureAttempted;
    private String instance;
    private int windowId=-1;
    private long lastEpoch;
    private JSONObject cleanup;
    private RemoteReply pendingCapture;
    private IBinder lifetime;
    private IBinder.DeathRecipient death;
    private final LinkedHashMap<String,String> used=new LinkedHashMap<String,String>();
    private int diagnostics;
    private JSONObject lastSuccessfulCapture;
    private final java.util.Set<String> attemptedLinkTargets=new java.util.LinkedHashSet<String>();
    private final java.util.Set<String> attemptedLinkRuns=new java.util.LinkedHashSet<String>();

    private EvidenceSession(Context context)throws Exception{
        this.context=context;files=new EvidenceFiles(context);processIdentity=ProcessIdentity.get(context);
        previousRaw=files.readJournalRaw();
        previous=previousRaw==null?null:Jsons.parseEvidence(new String(previousRaw,StandardCharsets.UTF_8),65536);
        if(previous!=null){
            String schema=previous.getString("schema");
            Jsons.need(schema.equals("hepta.web-helper.lease-journal.v1")||schema.equals("hepta.web-helper.lease-journal.v2")
                    ||schema.equals("hepta.web-helper.lease-journal.v3")||schema.equals(WebEvidenceProtocol.JOURNAL_SCHEMA),"unknown helper journal");
            Jsons.need(WebEvidenceBinding.sha256(previous.getJSONObject("binding")).equals(previous.getString("binding_sha256")),"previous binding hash differs");
            String state=previous.optString("state");
            if("closed".equals(state)){
                // A historical v2 CLOSED record still needs its actual storage callback fact.
                // Unresolved historical bindings are preserved as unknown, never converted to v3 authority.
                orphan=schema.equals("hepta.web-helper.lease-journal.v1")?!legacyCleanup(previous.optJSONObject("cleanup")):!allCleanup(previous.optJSONObject("cleanup"));
            }else if("unstarted_retired".equals(state)&&schema.equals(WebEvidenceProtocol.JOURNAL_SCHEMA)){
                unstartedRecord=files.reference(previous.getJSONObject("unstarted_record"));
                JSONObject initial=files.readObject(unstartedRecord),verified=WebRecoveryPolicy.evaluateUnstartedRecord(initial);
                orphan=!WebEvidenceProtocol.UNSTARTED_SCHEMA.equals(initial.optString("schema"))
                        ||!Boolean.TRUE.equals(verified.opt("retirement_verified"))
                        ||!previous.getString("binding_sha256").equals(verified.optString("binding_sha256"));
            }else if("recovered_retired".equals(state)&&schema.equals(WebEvidenceProtocol.JOURNAL_SCHEMA)){
                recoveredRecord=files.reference(previous.getJSONObject("recovery_record"));
                recoveredVerdict=WebRecoveryPolicy.evaluateRecord(files.readObject(recoveredRecord));
                orphan=!Boolean.TRUE.equals(recoveredVerdict.opt("retirement_verified"))
                        ||!previous.getString("binding_sha256").equals(recoveredVerdict.optString("binding_sha256"));
            }else orphan=true;
            JSONArray history=previous.optJSONArray("consumed_close_nonces");
            if(history!=null){Jsons.need(history.length()<=1024,"stored close history byte-bounded count");for(int i=0;i<history.length();i++){
                Object nonce=history.get(i);Jsons.need(nonce instanceof String&&WebEvidenceProtocol.hex64((String)nonce)&&closeHistory.add((String)nonce),"invalid/repeated stored close history");}}
            JSONObject saved=previous.optJSONObject("close_requests");
            if(saved!=null){java.util.Iterator<String> names=saved.keys();while(names.hasNext()){String key=names.next();closeUsed.put(key,saved.getJSONObject(key));}}
            pruneCloseNonces();
        }
        DisplayManager dm=(DisplayManager)context.getSystemService(Context.DISPLAY_SERVICE);
        dm.registerDisplayListener(new DisplayManager.DisplayListener(){
            public void onDisplayAdded(int id){}public void onDisplayChanged(int id){if(binding!=null&&!retired&&id==binding.displayId)checkLease();}
            public void onDisplayRemoved(int id){if(binding!=null&&!retired&&id==binding.displayId)retire("owned_display_removed");}
        },ui);
    }
    boolean register(PageActivity candidate){
        requireUi();if(orphan||recoveryInProgress||manualCleanupPending||(page!=null&&page!=candidate)||binding!=null&&!retired)return false;
        page=candidate;return true;
    }
    boolean canDiagnose(PageActivity candidate){requireUi();return !orphan&&!recoveryInProgress&&!manualCleanupPending&&page==candidate&&(binding==null||retired)&&candidate.actualDisplayId()==0;}
    boolean isBound(PageActivity candidate){return page==candidate&&binding!=null&&!retired;}
    void requirePage(PageActivity candidate)throws Exception{
        requireUi();Jsons.need(page==candidate&&!orphan,"page not owned by current helper process");
        if(binding!=null&&!retired){binding.requireActive(context);candidate.requireBinding(binding,instance,windowId);}
        else Jsons.need(candidate.diagnosticActive()&&canDiagnose(candidate),"diagnostic page not explicitly opened");
    }
    JSONObject pageBinding(PageActivity candidate)throws Exception{
        requirePage(candidate);
        if(binding!=null&&!retired)return new JSONObject(WebEvidenceBinding.canonical(binding.evidence));
        return new JSONObject().put("schema","hepta.web-helper.unbound-diagnostic.v2").put("task_id",JSONObject.NULL)
                .put("display_id",0).put("actor","manual_native_open").put("grants_task_authority",false)
                .put("goal_kind",candidate.pageKind()).put("site_policy_id",candidate.pagePolicyId())
                .put("site_policy_sha256",candidate.pagePolicyHash()).put("initial_url",candidate.pageInitialUrl())
                .put("site_policy",candidate.pagePolicy());
    }
    void pageDestroyed(PageActivity candidate){
        requireUi();if(page!=candidate&&retiringPage!=candidate)return;
        if(candidate.boundPage()){
            if(binding!=null&&!retired)retire("activity_destroyed");
        }else retireDiagnostic(candidate);
        if(page==candidate)page=null;
    }
    void diagnosticFailed(PageActivity candidate){
        requireUi();if(page==candidate)retireDiagnostic(candidate);
    }
    private void retireDiagnostic(PageActivity candidate){
        if(manualCleanupPending)return;
        manualCleanupPending=true;retiringPage=candidate;
        try{
            candidate.destroyForLease();
            if(candidate.neverStartedResources()){
                files.write("diagnostic-unstarted",UUID.randomUUID().toString(),new JSONObject()
                        .put("schema","hepta.web-helper.diagnostic-unstarted.v1").put("cleanup",candidate.currentCleanup())
                        .put("resources_never_started",true).put("business_verified",false));
                manualCleanupPending=false;if(retiringPage==candidate)retiringPage=null;return;
            }
            candidate.clearStorageAfterRetirement(SystemClock.elapsedRealtime()+ProfileIsolation.CLEAR_BUDGET_MS,(ok,facts,reason)->{
                manualCleanupPending=!ok;
                try{files.write("diagnostic-close",UUID.randomUUID().toString(),new JSONObject()
                        .put("schema","hepta.web-helper.diagnostic-close.v2").put("cleanup",candidate.currentCleanup())
                        .put("storage_isolation",facts).put("reason",reason).put("business_verified",false));}
                catch(Exception unavailable){manualCleanupPending=true;}
                if(ok&&retiringPage==candidate)retiringPage=null;
            });
        }catch(Exception unavailable){manualCleanupPending=true;}
    }
    void dispatch(RemoteReply reply){ui.post(()->handle(reply));}
    void serviceStopped(){ui.post(()->{if(binding!=null&&!retired)retire("evidence_service_destroyed");});}
    private void handle(RemoteReply reply){
        requireUi();try{
            TaskBinding.validateCommon(reply.request,reply.method);
            reply.controller.requireUnchanged(context);reply.helper.requireUnchanged(context);
            if(reply.method==WebEvidenceProtocol.ATTACH){attach(reply);return;}
            if(reply.method==WebEvidenceProtocol.CLOSE){
                if(binding!=null){requireSame(reply);consumeClose(reply);close(reply);return;}
                if(previous!=null){
                    requirePrevious(reply);
                    if(orphan){recoverPreviousClose(reply);return;}
                    if(closedFromPriorProcess(reply))return;
                }
                throw new IllegalArgumentException("no_matching_helper_lease");
            }
            Jsons.need(binding!=null&&!recoveryInProgress,"no_matching_helper_lease");
            requireSame(reply);consume(reply);
            if(reply.method==WebEvidenceProtocol.ARM_OBSERVED_LINK)armObservedLink(reply);else capture(reply);
        }catch(Exception failure){replyFailure(reply,"rejected",message(failure));}
    }
    private void attach(final RemoteReply reply)throws Exception{
        Jsons.need(!orphan&&!recoveryInProgress&&!manualCleanupPending&&!(binding!=null&&!retired),"helper lease already active or unknown");
        final TaskBinding next=TaskBinding.attach(reply.request,reply.controller,reply.helper,context);
        Jsons.need(Jsons.number(reply.request,"deadline_elapsed_ms")<=next.expires,"attach deadline exceeds lease");
        Jsons.need(page!=null&&page.canAttach(next),"fresh helper placeholder on owned display required");
        final PageActivity attachingPage=page;
        final String nextInstance=page.webviewInstance();final int nextWindow=page.actualWindowId();final long nextEpoch=page.navigationEpoch();
        DisplayManager displays=context.getSystemService(DisplayManager.class);
        Jsons.need(displays!=null&&nextWindow>=0&&WebEvidenceProtocol.uuid(nextInstance),"actual placeholder/display identity required");
        final JSONObject nextDisplay=NativeRetirementProbe.displayRecord(displays.getDisplay(next.displayId));
        binding=next;retired=false;cleanup=null;firstCaptureAttempted=false;used.clear();closeUsed.clear();closeHistory.clear();
        lastSuccessfulCapture=null;attemptedLinkTargets.clear();attemptedLinkRuns.clear();
        recoveredRecord=null;recoveredVerdict=null;retiringPage=null;unstartedRecord=null;
        attachRequestRaw=reply.rawRequest;attachBoundElapsed=SystemClock.elapsedRealtime();
        instance=nextInstance;windowId=nextWindow;lastEpoch=nextEpoch;displayBefore=nextDisplay;
        try{
            consume(reply); // Original binding, process summary and display facts are durable before profile creation or URL loading.
            pendingAttach=reply;
            lifetime=reply.binder;death=()->ui.post(()->retire("controller_binder_died"));lifetime.linkToDeath(death,0);
            ui.postDelayed(()->{if(binding==next&&!retired)retire("lease_expired");},Math.max(1,next.expires-SystemClock.elapsedRealtime()));
            page.attachAndLoad(next,Jsons.number(reply.request,"deadline_elapsed_ms"),(ok,reason)->{
                try{
                    Jsons.need(ok&&pendingAttach==reply&&!retired&&binding==next&&page==attachingPage,"attach lifecycle changed");
                    TaskBinding.validateCommon(reply.request,reply.method);next.requireActive(context);page.requireBinding(next,instance,windowId);
                    lastEpoch=page.navigationEpoch();pendingAttach=null;persist("active");
                    send(reply,"attached",null,null,null);
                }catch(Exception failure){
                    if(pendingAttach==reply)pendingAttach=null;
                    retire("attach_failed");
                    replyFailure(reply,"unavailable",reason+": "+message(failure));
                }
            });
        }catch(Exception failure){if(pendingAttach==reply)pendingAttach=null;retire("attach_failed");throw failure;}
    }
    private void requireSame(RemoteReply reply)throws Exception{
        Jsons.need(binding.taskId.equals(Jsons.text(reply.request,"task_id"))&&binding.sessionNonce.equals(Jsons.text(reply.request,"controller_session_nonce")),"task/session differs");
        binding.controller.requireRequest(reply.controller.evidence);binding.helper.requireRequest(reply.helper.evidence);
        binding.requireIdentity(context); // Closing remains possible after expiry/display loss.
    }
    private void consume(RemoteReply reply)throws Exception{
        String nonce=Jsons.text(reply.request,"request_nonce");Jsons.need(!used.containsKey(nonce)&&!closeHistory.contains(nonce)&&!closeUsed.containsKey(nonce),"request_nonce_already_consumed");
        Jsons.need(used.size()<WebEvidenceProtocol.MAX_REQUESTS_PER_SESSION,"request count budget");
        used.put(nonce,Jsons.sha(reply.rawRequest));persist(currentJournalState());
    }
    private void pruneCloseNonces()throws Exception{
        long now=SystemClock.elapsedRealtime();int boot=processIdentity.snapshot().getInt("boot_count");
        java.util.Iterator<Map.Entry<String,JSONObject>> it=closeUsed.entrySet().iterator();
        while(it.hasNext()){
            Map.Entry<String,JSONObject> row=it.next();JSONObject value=row.getValue();
            Jsons.need(WebEvidenceProtocol.hex64(row.getKey()),"invalid stored close nonce");
            Jsons.keys(value,new java.util.TreeSet<String>(java.util.Arrays.asList("request_sha256","deadline_elapsed_ms","boot_count")));
            Jsons.need(WebEvidenceProtocol.hex64(Jsons.text(value,"request_sha256")),"invalid stored close request hash");
            if(Jsons.integer(value,"boot_count")!=boot||Jsons.number(value,"deadline_elapsed_ms")<=now)it.remove();
        }
        Jsons.need(closeUsed.size()<=WebEvidenceProtocol.MAX_CLOSE_REQUESTS_IN_WINDOW,"stored close request budget");
    }
    private void consumeClose(RemoteReply reply)throws Exception{
        pruneCloseNonces();String nonce=Jsons.text(reply.request,"request_nonce");
        JSONObject previousUsed=previous==null?null:previous.optJSONObject("consumed_requests");
        Jsons.need(!used.containsKey(nonce)&&!closeHistory.contains(nonce)&&!closeUsed.containsKey(nonce)
                &&(binding!=null||previousUsed==null||!previousUsed.has(nonce)),"close request nonce already consumed");
        Jsons.need(closeUsed.size()<WebEvidenceProtocol.MAX_CLOSE_REQUESTS_IN_WINDOW,"current close window budget; new requests become available after expiry");
        closeHistory.add(nonce); // Permanent for this lease; expiry only prunes rate-window metadata, never nonce consumption.
        closeUsed.put(nonce,new JSONObject().put("request_sha256",Jsons.sha(reply.rawRequest))
                .put("deadline_elapsed_ms",Jsons.number(reply.request,"deadline_elapsed_ms"))
                .put("boot_count",processIdentity.snapshot().getInt("boot_count")));
        if(binding!=null)persist(currentJournalState());
        else{
            preservePrevious();JSONObject control=new JSONObject(previous.toString()).put("close_requests",closeRequests()).put("consumed_close_nonces",closeHistory());
            files.journal(control); // Original unknown bytes stay in preservedPrevious and previousRaw.
        }
    }
    private JSONArray closeHistory(){JSONArray out=new JSONArray();for(String nonce:closeHistory)out.put(nonce);return out;}
    private JSONObject closeRequests()throws Exception{
        JSONObject out=new JSONObject();for(Map.Entry<String,JSONObject> entry:closeUsed.entrySet())out.put(entry.getKey(),entry.getValue());return out;
    }
    private void preservePrevious()throws Exception{
        if(previousRaw!=null&&preservedPrevious==null)preservedPrevious=files.preserveUnresolved(previousRaw);
    }
    private void capture(final RemoteReply reply)throws Exception{
        Jsons.need(!retired&&!orphan&&page!=null,"helper lease retired");binding.requireActive(context);page.requireBinding(binding,instance,windowId);
        Jsons.need(Jsons.number(reply.request,"deadline_elapsed_ms")<=binding.expires,"capture deadline exceeds lease");
        Jsons.need(pendingCapture==null,"capture already pending");lastSuccessfulCapture=null;
        Object expectedInstance=reply.request.get("expected_webview_instance"),expectedEpoch=reply.request.get("expected_navigation_epoch");
        if(expectedInstance==JSONObject.NULL){Jsons.need(!firstCaptureAttempted,"first-capture null expectation already consumed");}
        else{
            Jsons.need(firstCaptureAttempted,"first capture must have null expectations");
            if(!instance.equals(expectedInstance)){retire("webview_instance_changed");throw new IllegalArgumentException("webview instance differs");}
        }
        firstCaptureAttempted=true;lastEpoch=page.navigationEpoch();
        if(expectedEpoch!=JSONObject.NULL){long expected=((Number)expectedEpoch).longValue();
            Jsons.need(expected<=lastEpoch,"expected navigation epoch is ahead");
            if(expected!=lastEpoch){send(reply,"state_changed","navigation_epoch_changed",null,null);return;}}
        final PageActivity originalPage=page;final TaskBinding originalBinding=binding;final long startedEpoch=lastEpoch;
        pendingCapture=reply;
        page.capture(Jsons.text(reply.request,"request_nonce"),Jsons.number(reply.request,"deadline_elapsed_ms"),new OfficialPageCapture.Callback(){
            public void captured(JSONObject captured){
                try{
                    Jsons.need(pendingCapture==reply&&!retired&&page==originalPage&&binding==originalBinding,"capture lease changed");
                    binding.requireActive(context);page.requireBinding(binding,instance,windowId);
                    JSONObject raw=new JSONObject().put("schema",WebEvidenceProtocol.RAW_SCHEMA)
                            .put("request_json_utf8",reply.rawRequest).put("request_sha256",Jsons.sha(reply.rawRequest))
                            .put("binding",binding.evidence).put("binding_sha256",binding.sha)
                            .put("controller_identity",reply.controller.evidence).put("helper_identity",reply.helper.evidence)
                            .put("actual_window_id",windowId).put("capture",captured).put("storage_isolation",page.storageEvidence())
                            .put("actor","controller_evidence_capture").put("diagnostic_unbound",false).put("business_verified",false);
                    WebStorageEvidence.requireCapture(binding.evidence,raw.getJSONObject("storage_isolation"),
                            captured.getLong("started_elapsed_ms"),captured.getLong("ended_elapsed_ms"));
                    fileWriter.execute(()->{
                        try{final EvidenceFiles.Record record=files.write("capture",reply.request.getString("request_nonce"),raw);
                            ui.post(()->{
                                try{
                                    Jsons.need(pendingCapture==reply&&!retired&&binding==originalBinding&&page==originalPage,"capture retired while storing");
                                    TaskBinding.validateCommon(reply.request,reply.method);binding.requireActive(context);page.requireBinding(binding,instance,windowId);
                                    Jsons.need(page.navigationEpoch()==startedEpoch,"navigation changed after capture");
                                    pendingCapture=null;lastEpoch=startedEpoch;
                                    lastSuccessfulCapture=new JSONObject(captured.toString());send(reply,"captured",null,record,null);
                                }catch(Exception failure){captureFailed(reply,startedEpoch,message(failure));}
                            });
                        }catch(Exception failure){ui.post(()->captureFailed(reply,startedEpoch,message(failure)));}
                    });
                }catch(Exception failure){captureFailed(reply,startedEpoch,message(failure));}
            }
            public void failed(String reason){captureFailed(reply,startedEpoch,reason);}
        });
    }
    private void captureFailed(RemoteReply reply,long startedEpoch,String reason){
        requireUi();lastSuccessfulCapture=null;if(pendingCapture==reply)pendingCapture=null;if(reply.alreadyReplied())return;
        try{
            if(!retired&&page!=null&&instance.equals(page.webviewInstance())&&page.navigationEpoch()>startedEpoch){lastEpoch=page.navigationEpoch();send(reply,"state_changed",reason,null,null);}
            else send(reply,"unavailable",reason,null,null);
        }catch(Exception ignored){retire("capture_callback_failed");}
    }
    private void armObservedLink(final RemoteReply reply)throws Exception{
        Jsons.need(!retired&&!orphan&&page!=null&&pendingCapture==null,"current completed formal capture required");
        binding.requireActive(context);page.requireBinding(binding,instance,windowId);
        org.trillionnium.hepta.webprotocol.WebObservedNavigation.requireRequest(reply.request);
        String target=Jsons.text(reply.request,"expected_webview_instance")+"|"
                +Jsons.number(reply.request,"expected_navigation_epoch")+"|"+Jsons.text(reply.request,"anchor_dom_path");
        String run=Jsons.text(reply.request,"model_run_id");
        Jsons.need(attemptedLinkTargets.size()<WebEvidenceProtocol.MAX_REQUESTS_PER_SESSION
                &&!attemptedLinkTargets.contains(target)&&!attemptedLinkRuns.contains(run),"observed-link attempt already consumed");
        // Fence before checking the candidate capture. Failure/unknown never
        // makes this lease+instance+epoch+anchor or native run eligible again.
        attemptedLinkTargets.add(target);attemptedLinkRuns.add(run);persist(currentJournalState());
        JSONObject source=lastSuccessfulCapture;lastSuccessfulCapture=null;
        try{
            Jsons.need(source!=null,"the private last successful fresh capture is absent");
            page.requireArmSource(source);
            JSONObject arm=org.trillionnium.hepta.webprotocol.WebObservedNavigation.arm(reply.request,binding.evidence,source,SystemClock.elapsedRealtime());
            JSONObject raw=new JSONObject().put("schema",WebEvidenceProtocol.RAW_SCHEMA)
                    .put("request_json_utf8",reply.rawRequest).put("request_sha256",Jsons.sha(reply.rawRequest))
                    .put("binding",binding.evidence).put("binding_sha256",binding.sha)
                    .put("controller_identity",reply.controller.evidence).put("helper_identity",reply.helper.evidence)
                    .put("actual_window_id",windowId).put("arm",arm).put("storage_isolation",page.storageEvidence())
                    .put("actor","controller_observed_link_arm").put("diagnostic_unbound",false).put("business_verified",false);
            // Small bounded immutable receipt; the source capture was already
            // durably written before it entered lastSuccessfulCapture.
            Jsons.need(raw.toString().getBytes(StandardCharsets.UTF_8).length<=65536,"bounded observed-link ARM receipt");
            EvidenceFiles.Record record=files.write("link-arm",Jsons.text(reply.request,"request_nonce"),raw);
            TaskBinding.validateCommon(reply.request,reply.method);binding.requireActive(context);page.requireBinding(binding,instance,windowId);
            page.installObservedLinkArm(arm,source);lastEpoch=page.navigationEpoch();
            try{send(reply,"armed","one_observed_public_link_armed",record,null);}
            catch(Exception callbackFailure){page.invalidateObservedLink("arm_callback_failed");throw callbackFailure;}
        }catch(Exception failure){
            if(page!=null)page.invalidateObservedLink("arm_rejected");
            throw failure;
        }
    }
    private void close(final RemoteReply reply)throws Exception{
        Jsons.need(pendingClose==null,"another matching cleanup reply is pending");
        pendingClose=reply;
        long deadline=Jsons.number(reply.request,"deadline_elapsed_ms");
        ui.postDelayed(()->{
            if(pendingClose==reply){pendingClose=null;replyFailure(reply,"unavailable","cleanup callback did not complete in this close RPC");}
        },Math.max(1,deadline-SystemClock.elapsedRealtime()));
        if(!retired)retire("controller_close_"+Jsons.text(reply.request,"reason"),deadline);
        else{
            if(finishUnstartedIfKnown())return;
            refreshCleanup();
            if(!allCleanup(cleanup)&&!storagePending&&retiringPage!=null)beginStorageRetirement(deadline,"fresh_close_readback",Jsons.text(reply.request,"request_nonce"));
            finishCloseIfKnown();
        }
    }
    void retire(String reason){retire(reason,SystemClock.elapsedRealtime()+ProfileIsolation.CLEAR_BUDGET_MS);}
    private void retire(String reason,long deadline){
        requireUi();if(binding==null||retired)return;retired=true;lastSuccessfulCapture=null;
        try{
            retiringPage=page;
            if(retiringPage!=null){lastEpoch=retiringPage.navigationEpoch();cleanup=retiringPage.destroyForLease();}
            else cleanup=new JSONObject().put("captures_retired",false).put("stop_loading_called",false)
                    .put("webview_destroyed",false).put("active_view_absent",true).put("storage_clear_completed",false);
            RemoteReply pending=pendingCapture;pendingCapture=null;
            if(pending!=null&&!pending.alreadyReplied())send(pending,"unavailable","lease_retired",null,null);
            RemoteReply attach=pendingAttach;pendingAttach=null;
            if(attach!=null&&!attach.alreadyReplied())send(attach,"unavailable","lease_retired_before_attach_completed",null,null);
            if(lifetime!=null&&death!=null)lifetime.unlinkToDeath(death,0);lifetime=null;death=null;
            orphan=!allCleanup(cleanup);persist(orphan?"unknown":"closed");
            writeCloseRecord(reason);
        }catch(Exception failure){orphan=true;try{persist("unknown");}catch(Exception ignored){}
            RemoteReply pending=pendingClose;pendingClose=null;if(pending!=null)replyFailure(pending,"unavailable",message(failure));
        }finally{
            // Private evidence I/O failure must not suppress this lease's actual storage retirement.
            // Unknown journal/proof stays unknown; the asynchronous cleanup still has its real deadline.
            try{beginStorageRetirement(deadline,reason,pendingClose==null?null:Jsons.text(pendingClose.request,"request_nonce"));}
            catch(Exception failure){orphan=true;try{persist("unknown");}catch(Exception ignored){}
                RemoteReply pending=pendingClose;pendingClose=null;if(pending!=null)replyFailure(pending,"unavailable",message(failure));}
        }
    }
    private void beginStorageRetirement(long deadline,String reason,String freshCloseNonce)throws Exception{
        if(retiringPage==null||storagePending)return;
        if(retiringPage.neverStartedResources()){finishUnstartedIfKnown();return;}
        final PageActivity original=retiringPage;final TaskBinding originalBinding=binding;
        storagePending=true;
        try{original.clearStorageAfterRetirement(deadline,freshCloseNonce,(ok,facts,why)->{
            try{
                if(binding!=originalBinding||retiringPage!=original)return;
                storagePending=false;refreshCleanup();orphan=!allCleanup(cleanup);
                persist(orphan?"unknown":"closed");writeCloseRecord(reason+":"+why);
                if(allCleanup(cleanup))finishCloseIfKnown();
                else{
                    RemoteReply pending=pendingClose;pendingClose=null;
                    if(pending!=null)send(pending,"unavailable","actual helper/storage cleanup remains incomplete",null,cleanup);
                }
            }catch(Exception failure){storagePending=false;orphan=true;RemoteReply pending=pendingClose;pendingClose=null;
                try{persist("unknown");}catch(Exception ignored){}if(pending!=null)replyFailure(pending,"unavailable",message(failure));}
        });}catch(Exception failure){storagePending=false;throw failure;}
    }
    private void refreshCleanup()throws Exception{
        if(retiringPage!=null){JSONObject actual=retiringPage.currentCleanup();if(actual!=null)cleanup=actual;}
        if(cleanup!=null&&allCleanup(cleanup)){orphan=false;persist("closed");}
    }
    private void finishCloseIfKnown()throws Exception{
        if(pendingClose==null)return;refreshCleanup();if(!allCleanup(cleanup))return;
        RemoteReply reply=pendingClose;pendingClose=null;
        TaskBinding.validateCommon(reply.request,reply.method);requireSame(reply);
        send(reply,"closed","matching_owned_page_and_recorded_profile_closed",null,cleanup);
    }
    private void writeCloseRecord(String reason)throws Exception{
        files.write("close",UUID.randomUUID().toString(),new JSONObject().put("schema","hepta.web-helper.close-evidence.v2")
                .put("binding",binding.evidence).put("binding_sha256",binding.sha).put("reason",bounded(reason))
                .put("helper_pid",Process.myPid()).put("process_identity",processIdentity.snapshot())
                .put("elapsed_ms",SystemClock.elapsedRealtime()).put("cleanup",cleanup==null?JSONObject.NULL:cleanup)
                .put("storage_isolation",retiringPage==null?JSONObject.NULL:retiringPage.storageEvidence())
                .put("destruction_diagnostics",retiringPage==null?JSONObject.NULL:retiringPage.destructionEvidence())
                .put("os_socket_closure_verified",false).put("business_verified",false));
    }
    private void requirePrevious(RemoteReply reply)throws Exception{
        Jsons.need(previous!=null,"previous lease missing");
        JSONObject saved=previous.getJSONObject("binding");
        Jsons.need(WebEvidenceBinding.sha256(saved).equals(previous.getString("binding_sha256")),"previous binding hash differs");
        Jsons.need(saved.getString("task_id").equals(Jsons.text(reply.request,"task_id"))
                &&saved.getString("controller_session_nonce").equals(Jsons.text(reply.request,"controller_session_nonce")),"previous close task/session differs");
        reply.controller.requireRequest(saved.getJSONObject("controller_identity"));
        reply.helper.requireRequest(saved.getJSONObject("helper_identity"));
        reply.controller.requireUnchanged(context);reply.helper.requireUnchanged(context);
    }
    private boolean closedFromPriorProcess(RemoteReply reply)throws Exception{
        if(previous==null)return false;requirePrevious(reply);
        if("unstarted_retired".equals(previous.optString("state"))&&!orphan){
            consumeClose(reply);sendUnstartedConfirmation(reply);return true;
        }
        if("recovered_retired".equals(previous.optString("state"))){
            recoverPreviousClose(reply);return true; // Fresh nonce and fresh OS/profile proof, never rewrite old destroy facts.
        }
        if(orphan||!"closed".equals(previous.optString("state")))return false;
        JSONObject oldCleanup=previous.optJSONObject("cleanup");
        Jsons.need(WebEvidenceProtocol.JOURNAL_SCHEMA.equals(previous.getString("schema"))&&allCleanup(oldCleanup),
                "historical closed record is not this v3 protocol or has no storage cleanup proof");
        consumeClose(reply);
        JSONObject out=base(reply,"closed","previous_process_closed_receipt");
        JSONObject saved=previous.getJSONObject("binding"),bg=saved.getJSONObject("background");
        out.put("actual_display_id",bg.getInt("display_id")).put("actual_window_id",previous.getInt("window_id"))
                .put("webview_instance",previous.getString("webview_instance")).put("navigation_epoch",previous.getLong("navigation_epoch"))
                .put("binding_sha256",previous.getString("binding_sha256")).put("retired",true).put("cleanup",oldCleanup);
        reply.send(out,null);return true;
    }
    private NativeRetirementProbe.OwnedState ownedState(){
        return new NativeRetirementProbe.OwnedState(){
            public int liveWebViewCount(){
                int count=page==null?0:page.liveWebViewCount();
                if(retiringPage!=null&&retiringPage!=page)count+=retiringPage.liveWebViewCount();
                return count;
            }
            public int pendingCaptureCount(){
                int count=pendingCapture==null?0:1;
                if(page!=null)count+=page.pendingCaptureCount();
                if(retiringPage!=null&&retiringPage!=page)count+=retiringPage.pendingCaptureCount();
                return count;
            }
        };
    }
    private void recoverPreviousClose(final RemoteReply reply)throws Exception{
        Jsons.need(binding==null&&previous!=null&&!recoveryInProgress&&pendingAttach==null&&!manualCleanupPending,
                "recovery cannot overlap a current helper lease or owned work");
        requirePrevious(reply);
        final byte[] priorBytes;
        if("recovered_retired".equals(previous.optString("state"))){
            EvidenceFiles.Record oldRecord=files.reference(previous.getJSONObject("recovery_record"));
            JSONObject oldRaw=files.readObject(oldRecord),oldVerdict=WebRecoveryPolicy.evaluateRecord(oldRaw);
            Jsons.need(Boolean.TRUE.equals(oldVerdict.opt("retirement_verified")),"stored recovery proof invalid");
            priorBytes=oldRaw.getString("prior_journal_utf8").getBytes(StandardCharsets.UTF_8);
        }else priorBytes=previousRaw.clone();
        final JSONObject prior=Jsons.parseEvidence(new String(priorBytes,StandardCharsets.UTF_8),65536);
        Jsons.need(previous.getString("binding_sha256").equals(prior.getString("binding_sha256")),"recovery prior binding differs");
        final EvidenceFiles.Record preserved=files.preserveUnresolved(priorBytes);
        final JSONObject before=NativeRetirementProbe.collect(context,prior,processIdentity,ownedState());
        JSONObject verdict=WebRecoveryPolicy.evaluate(prior,before);
        Jsons.need(Boolean.TRUE.equals(verdict.opt("verified")),"native retirement evidence unavailable:"+verdict.optString("reason"));
        consumeClose(reply); // Durable nonce consumption before any recorded-profile cleanup.
        recoveryInProgress=true;recoveryReply=reply;
        final long deadline=Jsons.number(reply.request,"deadline_elapsed_ms");
        ui.postDelayed(()->{
            if(recoveryReply==reply){recoveryReply=null;recoveryInProgress=false;
                replyFailure(reply,"unavailable","retirement RPC deadline exceeded; original unknown is retained");}
        },Math.max(1,deadline-SystemClock.elapsedRealtime()));
        JSONObject oldBinding=prior.getJSONObject("binding");
        if(oldBinding.has("storage_profile_name")){
            try{
                RetiredProfileClear.start(oldBinding,deadline,(ok,storage,reason)->{
                    if(!ok){recoveryFailed(reply,priorBytes,before,storage,reason);return;}
                    finishRecovery(reply,priorBytes,prior,preserved,before,storage);
                });
            }catch(Exception failure){recoveryFailed(reply,priorBytes,before,null,message(failure));}
        }else{
            JSONObject storage=new JSONObject().put("schema","hepta.web-helper.recovery-storage-legacy.v1")
                    .put("kind","legacy_profile_unrecorded").put("profile_name",JSONObject.NULL)
                    .put("clear_invoked",false).put("storage_retirement_verified",false);
            // Pure policy permits this only after an actual greater boot count. Default profile is never touched.
            finishRecovery(reply,priorBytes,prior,preserved,before,storage);
        }
    }
    private void finishRecovery(RemoteReply reply,byte[] priorBytes,JSONObject prior,EvidenceFiles.Record preserved,
                                JSONObject before,JSONObject storage){
        requireUi();
        try{
            Jsons.need(recoveryInProgress&&recoveryReply==reply&&!reply.alreadyReplied()&&binding==null,"recovery reply/session changed");
            TaskBinding.validateCommon(reply.request,reply.method);requirePrevious(reply);
            JSONObject after=NativeRetirementProbe.collect(context,prior,processIdentity,ownedState());
            JSONObject oldBinding=prior.getJSONObject("binding");
            JSONObject raw=new JSONObject().put("schema",WebEvidenceProtocol.RECOVERY_SCHEMA)
                    .put("request_json_utf8",reply.rawRequest).put("request_sha256",Jsons.sha(reply.rawRequest))
                    .put("binding",oldBinding).put("binding_sha256",prior.getString("binding_sha256"))
                    .put("prior_journal_utf8",new String(priorBytes,StandardCharsets.UTF_8))
                    .put("prior_journal_bytes",priorBytes.length).put("prior_journal_sha256",Jsons.sha(priorBytes))
                    .put("preserved_prior_record",preserved.reference()).put("original_cleanup",prior.get("cleanup"))
                    .put("actual_controller_identity",reply.controller.evidence).put("actual_helper_identity",reply.helper.evidence)
                    .put("native_probe_before",before).put("native_probe_after",after).put("storage_retirement",storage)
                    .put("completed_elapsed_ms",SystemClock.elapsedRealtime())
                    .put("old_cleanup_methods_verified",false).put("business_verified",false);
            JSONObject verified=WebRecoveryPolicy.evaluateRecord(raw);
            Jsons.need(Boolean.TRUE.equals(verified.opt("retirement_verified")),"retirement record invalid:"+verified.optString("reason"));
            EvidenceFiles.Record record=files.write("recovered",reply.request.getString("request_nonce"),raw);
            TaskBinding.validateCommon(reply.request,reply.method);requirePrevious(reply);
            JSONObject journal=new JSONObject(prior.toString()).put("schema",WebEvidenceProtocol.JOURNAL_SCHEMA)
                    .put("state","recovered_retired").put("close_requests",closeRequests()).put("consumed_close_nonces",closeHistory())
                    .put("recovery_record",record.reference()).put("recovery_process_identity",processIdentity.snapshot())
                    .put("recovered_elapsed_ms",SystemClock.elapsedRealtime());
            preservePrevious();files.journal(journal);
            previous=journal;previousRaw=(journal.toString()+"\n").getBytes(StandardCharsets.UTF_8);preservedPrevious=null;
            recoveredRecord=record;recoveredVerdict=verified;orphan=false;recoveryInProgress=false;recoveryReply=null;
            JSONObject out=base(reply,"recovered_retired","original_lease_retired_by_independent_os_and_recorded_profile_evidence")
                    .put("binding_sha256",prior.getString("binding_sha256")).put("retired",true)
                    .put("cleanup",prior.get("cleanup")).put("recovery",verified)
                    .put("raw_length",record.length).put("raw_sha256",record.sha);
            // actual display/window remain -1: prior IDs are preserved in the FD binding, not represented as live.
            reply.send(out,record);
        }catch(Exception failure){recoveryFailed(reply,priorBytes,before,storage,message(failure));}
    }
    private void recoveryFailed(RemoteReply reply,byte[] priorBytes,JSONObject before,JSONObject storage,String reason){
        requireUi();
        if(recoveryReply!=reply||reply.alreadyReplied())return;
        recoveryReply=null;recoveryInProgress=false;
        try{files.write("recovery-failed",reply.request.getString("request_nonce"),new JSONObject()
                .put("schema","hepta.web-helper.recovery-attempt.v1").put("request_sha256",Jsons.sha(reply.rawRequest))
                .put("prior_journal_sha256",Jsons.sha(priorBytes)).put("native_probe_before",before)
                .put("storage_retirement",storage==null?JSONObject.NULL:new JSONObject(storage.toString()))
                .put("reason",bounded(reason)).put("retirement_verified",false).put("business_verified",false));}
        catch(Exception ignored){}
        replyFailure(reply,"unavailable",reason);
    }

    private String currentJournalState()throws Exception{
        if(unstartedRecord!=null)return "unstarted_retired";
        return retired?(allCleanup(cleanup)?"closed":"unknown"):"active";
    }
    private byte[] readUnstartedRaw(EvidenceFiles.Record record)throws Exception{
        record.verify();Jsons.need(record.length>0&&record.length<=WebEvidenceProtocol.MAX_UNSTARTED_RECORD_BYTES,"initial unstarted record budget");
        java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream();
        try(java.io.FileInputStream in=new java.io.FileInputStream(record.path)){
            byte[] buffer=new byte[4096];int n;
            while((n=in.read(buffer))!=-1){Jsons.need(out.size()+n<=record.length,"initial unstarted raw grew");out.write(buffer,0,n);}
        }
        byte[] raw=out.toByteArray();Jsons.need(raw.length==record.length&&record.sha.equals(Jsons.sha(raw)),"initial unstarted original bytes differ");
        record.verify();return raw;
    }
    private boolean finishUnstartedIfKnown()throws Exception{
        if(pendingClose==null)return false;
        final RemoteReply reply=pendingClose;
        if(unstartedRecord!=null){sendUnstartedConfirmation(reply);pendingClose=null;return true;}
        if(!retired||retiringPage==null||!retiringPage.neverStartedResources()||attachRequestRaw==null)return false;
        TaskBinding.validateCommon(reply.request,reply.method);requireSame(reply);
        Jsons.need(!storagePending&&pendingAttach==null&&pendingCapture==null&&!recoveryInProgress,
                "unstarted proof cannot overlap owned work");
        final PageActivity original=retiringPage;
        long began=SystemClock.elapsedRealtime();
        JSONObject processBefore=processIdentity.snapshot(),before=original.unstartedResourceFence();
        byte[] priorBytes=files.readJournalRaw();Jsons.need(priorBytes!=null,"original unknown journal unavailable");
        JSONObject prior=Jsons.parseEvidence(new String(priorBytes,StandardCharsets.UTF_8),65536);
        Jsons.need("unknown".equals(prior.getString("state"))&&binding.sha.equals(prior.getString("binding_sha256")),
                "unstarted original journal is not this unresolved lease");
        EvidenceFiles.Record preserved=files.preserveUnresolved(priorBytes);
        JSONObject after=original.unstartedResourceFence(),processAfter=processIdentity.snapshot();
        long ended=SystemClock.elapsedRealtime();
        JSONObject raw=new JSONObject().put("schema",WebEvidenceProtocol.UNSTARTED_SCHEMA)
                .put("request_json_utf8",reply.rawRequest).put("request_sha256",Jsons.sha(reply.rawRequest))
                .put("binding",binding.evidence).put("binding_sha256",binding.sha)
                .put("attach_request_json_utf8",attachRequestRaw).put("attach_request_sha256",Jsons.sha(attachRequestRaw))
                .put("attach_bound_elapsed_ms",attachBoundElapsed)
                .put("prior_journal_utf8",new String(priorBytes,StandardCharsets.UTF_8))
                .put("prior_journal_bytes",priorBytes.length).put("prior_journal_sha256",Jsons.sha(priorBytes))
                .put("preserved_prior_record",preserved.reference()).put("original_cleanup",prior.get("cleanup"))
                .put("actual_controller_identity",reply.controller.evidence).put("actual_helper_identity",reply.helper.evidence)
                .put("process_identity_before",processBefore).put("process_identity_after",processAfter)
                .put("resource_fence_before",before).put("resource_fence_after",after)
                .put("started_elapsed_ms",began).put("completed_elapsed_ms",ended)
                .put("old_cleanup_methods_verified",false).put("business_verified",false);
        Jsons.need((raw.toString()+"\n").getBytes(StandardCharsets.UTF_8).length<=WebEvidenceProtocol.MAX_UNSTARTED_RECORD_BYTES,
                "complete unstarted proof byte budget");
        JSONObject verified=WebRecoveryPolicy.evaluateUnstartedRecord(raw);
        Jsons.need(Boolean.TRUE.equals(verified.opt("retirement_verified")),"unstarted proof refused:"+verified.optString("reason"));
        EvidenceFiles.Record record=files.write("unstarted",reply.request.getString("request_nonce"),raw);
        TaskBinding.validateCommon(reply.request,reply.method);requireSame(reply);
        Jsons.need(retired&&retiringPage==original&&original.neverStartedResources()&&ownedState().liveWebViewCount()==0
                &&ownedState().pendingCaptureCount()==0,"owned resources changed while storing unstarted evidence");
        unstartedRecord=record;persist("unstarted_retired");orphan=false;
        pendingClose=null;sendUnstarted(reply,record,raw,verified);
        return true;
    }
    private void sendUnstartedConfirmation(RemoteReply reply)throws Exception{
        Jsons.need(unstartedRecord!=null,"stored initial unstarted proof missing");
        TaskBinding.validateCommon(reply.request,reply.method);
        if(binding!=null)requireSame(reply);else requirePrevious(reply);
        Jsons.need(!recoveryInProgress&&!storagePending&&pendingAttach==null&&pendingCapture==null,
                "unstarted confirmation overlaps current owned work");
        long began=SystemClock.elapsedRealtime();byte[] originalBytes=readUnstartedRaw(unstartedRecord);
        JSONObject original=Jsons.parseEvidence(new String(originalBytes,StandardCharsets.UTF_8),WebEvidenceProtocol.MAX_UNSTARTED_RECORD_BYTES);
        Jsons.need(WebEvidenceProtocol.UNSTARTED_SCHEMA.equals(original.getString("schema")),"only initial unstarted proof can be confirmed");
        Jsons.need((binding!=null?binding.sha:previous.getString("binding_sha256")).equals(original.getString("binding_sha256")),"stored unstarted binding differs");
        JSONObject raw=new JSONObject().put("schema",WebEvidenceProtocol.UNSTARTED_CONFIRMATION_SCHEMA)
                .put("request_json_utf8",reply.rawRequest).put("request_sha256",Jsons.sha(reply.rawRequest))
                .put("binding_sha256",original.getString("binding_sha256"))
                .put("initial_record_utf8",new String(originalBytes,StandardCharsets.UTF_8))
                .put("initial_record_bytes",originalBytes.length).put("initial_record_sha256",Jsons.sha(originalBytes))
                .put("actual_controller_identity",reply.controller.evidence).put("actual_helper_identity",reply.helper.evidence)
                .put("current_process_identity",processIdentity.snapshot())
                .put("started_elapsed_ms",began).put("completed_elapsed_ms",SystemClock.elapsedRealtime())
                .put("active_bound_view_count",ownedState().liveWebViewCount()).put("pending_capture_count",ownedState().pendingCaptureCount())
                .put("old_cleanup_methods_verified",false).put("business_verified",false);
        JSONObject verified=WebRecoveryPolicy.evaluateUnstartedRecord(raw);
        Jsons.need(Boolean.TRUE.equals(verified.opt("retirement_verified")),"unstarted confirmation refused:"+verified.optString("reason"));
        EvidenceFiles.Record record=files.write("unstarted-confirm",reply.request.getString("request_nonce"),raw);
        TaskBinding.validateCommon(reply.request,reply.method);
        if(binding!=null)requireSame(reply);else requirePrevious(reply);
        Jsons.need(ownedState().liveWebViewCount()==0&&ownedState().pendingCaptureCount()==0,"owned work changed while storing confirmation");
        sendUnstarted(reply,record,original,verified);
    }
    private void sendUnstarted(RemoteReply reply,EvidenceFiles.Record record,JSONObject original,JSONObject verified)throws Exception{
        JSONObject out=base(reply,"unstarted_retired","matching_attachment_never_started_owned_web_resources")
                .put("binding_sha256",verified.getString("binding_sha256")).put("retired",true)
                .put("cleanup",original.get("original_cleanup")).put("recovery",verified)
                .put("raw_length",record.length).put("raw_sha256",record.sha);
        // These are retirement records, not a live window observation. Original IDs remain in the FD.
        reply.send(out,record);
    }

    private void persist(String state)throws Exception{
        Jsons.need(binding!=null,"binding missing for durable journal");JSONObject nonces=new JSONObject();
        for(Map.Entry<String,String> entry:used.entrySet())nonces.put(entry.getKey(),entry.getValue());
        preservePrevious();
        Object storage=page!=null?page.storageEvidence():retiringPage!=null?retiringPage.storageEvidence():JSONObject.NULL;
        files.journal(new JSONObject().put("schema",WebEvidenceProtocol.JOURNAL_SCHEMA).put("state",state)
                .put("binding",binding.evidence).put("binding_sha256",binding.sha).put("helper_pid",Process.myPid())
                .put("process_identity",processIdentity.snapshot()).put("display_before",displayBefore)
                .put("window_id",windowId).put("webview_instance",instance).put("navigation_epoch",lastEpoch)
                .put("cleanup",cleanup==null?JSONObject.NULL:cleanup).put("storage_isolation",storage)
                .put("attach_request_json_utf8",attachRequestRaw==null?JSONObject.NULL:attachRequestRaw)
                .put("attach_request_sha256",attachRequestRaw==null?JSONObject.NULL:Jsons.sha(attachRequestRaw))
                .put("attach_bound_elapsed_ms",attachBoundElapsed)
                .put("unstarted_record",unstartedRecord==null?JSONObject.NULL:unstartedRecord.reference())
                .put("consumed_requests",nonces).put("close_requests",closeRequests()).put("consumed_close_nonces",closeHistory())
                .put("observed_link_attempted_targets",new JSONArray(attemptedLinkTargets))
                .put("observed_link_attempted_model_runs",new JSONArray(attemptedLinkRuns))
                .put("previous_journal_reference",preservedPrevious==null?JSONObject.NULL:preservedPrevious.reference()));
    }
    private void checkLease(){try{binding.requireActive(context);if(page!=null)page.requireBinding(binding,instance,windowId);else throw new IllegalStateException("bound page absent");}catch(Exception lost){retire(message(lost));}}
    private void send(RemoteReply reply,String status,String reason,EvidenceFiles.Record raw,JSONObject close)throws Exception{
        JSONObject out=base(reply,status,reason);
        if(binding!=null)out.put("actual_display_id",binding.displayId).put("actual_window_id",windowId)
                .put("webview_instance",instance).put("navigation_epoch",lastEpoch).put("binding_sha256",binding.sha).put("retired",retired);
        if(raw!=null)out.put("raw_length",raw.length).put("raw_sha256",raw.sha);if(close!=null)out.put("cleanup",close);
        reply.send(out,raw);
    }
    private JSONObject base(RemoteReply reply,String status,String reason)throws Exception{
        return new JSONObject().put("schema",WebEvidenceProtocol.CALLBACK_SCHEMA).put("method",WebEvidenceProtocol.method(reply.method))
                .put("request_nonce",reply.request.getString("request_nonce")).put("task_id",reply.request.getString("task_id"))
                .put("controller_session_nonce",reply.request.getString("controller_session_nonce")).put("status",status)
                .put("reason",reason==null?JSONObject.NULL:bounded(reason)).put("actual_helper_uid",Process.myUid())
                .put("actual_display_id",-1).put("actual_window_id",-1).put("webview_instance",JSONObject.NULL)
                .put("navigation_epoch",JSONObject.NULL).put("binding_sha256",JSONObject.NULL).put("raw_length",0)
                .put("raw_sha256",JSONObject.NULL).put("retired",false).put("cleanup",JSONObject.NULL).put("recovery",JSONObject.NULL);
    }
    private void replyFailure(RemoteReply reply,String status,String reason){if(reply.alreadyReplied())return;try{send(reply,status,reason,null,null);}catch(Exception ignored){if(binding!=null&&!retired)retire("callback_failed");}}
    void diagnostic(PageActivity candidate,String cause){
        requireUi();if(!canDiagnose(candidate)||!candidate.diagnosticActive()||diagnostics>=WebEvidenceProtocol.MAX_DIAGNOSTICS)return;diagnostics++;
        try{String id=Jsons.sha(UUID.randomUUID().toString());candidate.capture(id,SystemClock.elapsedRealtime()+WebEvidenceProtocol.CAPTURE_MS,new OfficialPageCapture.Callback(){
            private DomInstabilityEvidence.Pair mismatch;
            private String mismatchStorage;
            private boolean finished;
            public void unstable(DomInstabilityEvidence.Pair pair)throws Exception{
                requireUi();
                if(finished||mismatch!=null||pair==null)throw new IllegalStateException("duplicate/stale manual mismatch pair");
                // No status/layout update while another read may still use this same native geometry.
                mismatch=pair;mismatchStorage=candidate.storageEvidence().toString();
            }
            private void writeMismatch()throws Exception{
                if(mismatch==null)return;
                JSONObject[] pair=mismatch.records(id,cause,mismatchStorage);
                files.write("diagnostic",Jsons.sha(id+":unstable:before"),pair[0]);
                files.write("diagnostic",Jsons.sha(id+":unstable:after"),pair[1]);
            }
            public void captured(JSONObject capture){
                requireUi();if(finished)return;finished=true;
                try{
                    String storageRaw=candidate.storageEvidence().toString();
                    JSONObject raw=new JSONObject().put("schema","hepta.web-helper.manual-diagnostic.v2")
                            .put("actor","manual_foreground_diagnostic").put("cause",cause).put("capture",capture)
                            .put("storage_isolation",new JSONObject(storageRaw)).put("task_id",JSONObject.NULL)
                            .put("diagnostic_unbound",true).put("business_verified",false);
                    fileWriter.execute(()->{try{
                        writeMismatch();
                        EvidenceFiles.Record r=files.write("diagnostic",id,raw);
                        ui.post(()->candidate.showRecord(r.path.getName(),r.sha));
                    }catch(Exception failure){ui.post(()->{if(candidate.pendingCaptureCount()==0)candidate.showProblem(message(failure));});}});
                }catch(Exception failure){candidate.showProblem(message(failure));}
            }
            public void failed(String reason){
                requireUi();if(finished)return;finished=true;
                candidate.showProblem("只读采集未完成："+reason);
                if(mismatch!=null)try{
                    fileWriter.execute(()->{try{writeMismatch();}
                        catch(Exception failure){ui.post(()->{if(candidate.pendingCaptureCount()==0)candidate.showProblem("只读失败诊断未完整保存："+message(failure));});}});
                }catch(Exception failure){candidate.showProblem("只读失败诊断未完整保存："+message(failure));}
            }
        });}catch(Exception failure){candidate.showProblem(message(failure));}
    }
    private static boolean legacyCleanup(JSONObject value)throws Exception{
        if(value==null)return false;
        java.util.TreeSet<String> keys=new java.util.TreeSet<String>(java.util.Arrays.asList("captures_retired","stop_loading_called","webview_destroyed","active_view_absent"));
        Jsons.keys(value,keys);for(String key:keys)if(!Boolean.TRUE.equals(value.get(key)))return false;return true;
    }
    private static boolean allCleanup(JSONObject value)throws Exception{
        if(value==null)return false;Jsons.keys(value,WebEvidenceProtocol.CLEANUP_KEYS);
        for(String key:WebEvidenceProtocol.CLEANUP_KEYS)if(!Boolean.TRUE.equals(value.get(key)))return false;return true;
    }
    private static String message(Exception failure){return bounded(failure.getMessage()==null?failure.getClass().getSimpleName():failure.getMessage());}
    private static String bounded(String text){return text==null?"unknown":text.length()>240?text.substring(0,240):text;}
    private static void requireUi(){Jsons.need(Looper.myLooper()==Looper.getMainLooper(),"helper UI thread required");}
}
