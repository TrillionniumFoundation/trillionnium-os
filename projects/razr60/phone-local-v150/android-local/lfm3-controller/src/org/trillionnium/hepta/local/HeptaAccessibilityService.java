package org.trillionnium.hepta.local;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.accessibilityservice.GestureDescription;
import android.app.KeyguardManager;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.graphics.Bitmap;
import android.graphics.Path;
import android.graphics.Rect;
import android.hardware.HardwareBuffer;
import android.hardware.display.DisplayManager;
import android.util.SparseArray;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.Display;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Standard Android accessibility service. All effects pass an observed-target gate. */
public final class HeptaAccessibilityService extends AccessibilityService {
    /** Only this service can construct a live native recheck token. It is not
     * reconstructed from a callback, serialized proof, or caller-supplied flag. */
    static final class NativeRegionCheck {
        private final PhoneObservation observedFrame;private final WebRegionNativeBridge observedBridge;
        final long checkedAt;private final String raw;
        private NativeRegionCheck(PhoneObservation frame,WebRegionNativeBridge bridge,long started,long ended,
                                  JSONObject windows)throws Exception{
            observedFrame=frame;observedBridge=bridge;checkedAt=ended;
            JSONObject value=new JSONObject().put("schema","hepta.live-native-region-recheck.v1")
                    .put("source","actual_accessibility_refresh_ancestry_and_interactive_windows")
                    .put("observation_id",frame.id).put("observation_state_sha256",frame.treeSha256)
                    .put("app_tree_sha256",frame.state.appTreeSha256).put("bridge_sha256",bridge.semanticFingerprint)
                    .put("binding_sha256",bridge.bindingSha).put("background_generation",bridge.generation)
                    .put("display_id",bridge.displayId).put("window_id",bridge.windowId)
                    .put("started_elapsed_ms",started).put("checked_elapsed_ms",ended)
                    .put("four_roles_refreshed_before_and_after",true)
                    .put("actual_parent_child_node_identity_verified",true)
                    .put("actual_native_webview_ancestor_verified",true)
                    .put("interactive_windows",windows).put("two_window_metadata_reads_equal",true)
                    .put("coordinates_used_for_input",false).put("fully_unoccluded_claimed",false)
                    .put("unreported_windows_excluded",false).put("native_invocation_entered",false)
                    .put("business_verified",false);
            raw=org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(value);
        }
        boolean matches(PhoneObservation frame,WebRegionNativeBridge bridge){
            return observedFrame==frame&&observedBridge==bridge&&frame!=null&&bridge!=null
                    &&frame.windowId==bridge.windowId&&frame.backgroundGeneration!=null
                    &&frame.backgroundGeneration.equals(bridge.generation);
        }
        JSONObject evidence()throws Exception{return new JSONObject(raw);}
    }
    /** Only the service may construct this token from a live graph and original NodeRef. */
    static final class FlightNativeCheck {
        private final PhoneObservation frame;private final WebFlightNativeStability.Permit permit;
        final long checkedAt;private final String raw;
        private FlightNativeCheck(PhoneObservation frame,WebFlightNativeStability.Permit permit,
                                  long started,long ended,JSONObject nativeProof,JSONObject windows,
                                  boolean originalDigestEqual)throws Exception{
            this.frame=frame;this.permit=permit;checkedAt=ended;
            raw=org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(new JSONObject()
                    .put("schema","hepta.flight-home-live-native-stability.v1").put("task_id",permit.taskId)
                    .put("model_run_id",permit.run).put("observation_id",frame.id)
                    .put("original_observation_state_sha256",frame.treeSha256)
                    .put("binding_sha256",permit.bindingSha).put("webview_instance",permit.instance)
                    .put("navigation_epoch",permit.epoch).put("display_id",permit.displayId).put("window_id",permit.windowId)
                    .put("started_elapsed_ms",started).put("checked_elapsed_ms",ended)
                    .put("original_global_digest_equal",originalDigestEqual).put("scope_is_compiled_home_booking_only",true)
                    .put("dom",permit.domEvidence()).put("native",nativeProof).put("interactive_windows",windows)
                    .put("original_node_ref_identity_preserved",true).put("actual_ancestor_chain_refreshed",true)
                    .put("two_interactive_window_reads_equal",true).put("ime_hidden",true)
                    .put("coordinates_used_for_input",false).put("fully_unoccluded_claimed",false)
                    .put("native_invocation_entered",false).put("business_verified",false));
        }
        boolean matches(PhoneObservation frame,WebFlightNativeStability.Permit permit){return this.frame==frame&&this.permit==permit;}
        JSONObject evidence()throws Exception{return new JSONObject(raw);}
    }
    /** Service-created read-only token. It owns one copied node and frozen graph evidence. */
    static final class FlightObservationSnapshot implements AutoCloseable {
        private final HeptaAccessibilityService service;private final WebFlightSession web;
        private final BackgroundSession background;private final QualificationScopeConfig.Bound scope;
        private final TaskAuthorization.Gate authorization;private final PhoneObservation frame;
        private final Graph graph;private final NodeRef original;private final String nodeId,targetPath,ownerSha,selectionRaw;
        private final long retainedAt;private volatile boolean closed;
        // Sealed by the waiting worker before publication; never encoded on main.
        private String frameRaw;
        private FlightObservationSnapshot(HeptaAccessibilityService service,WebFlightSession web,
                BackgroundSession background,QualificationScopeConfig.Bound scope,TaskAuthorization.Gate authorization,
                PhoneObservation frame,Graph graph,String nodeId,String targetPath,long at,String frameRaw){
            this.service=service;this.web=web;this.background=background;this.scope=scope;this.authorization=authorization;
            this.frame=frame;this.graph=graph;this.nodeId=nodeId;this.targetPath=targetPath;this.frameRaw=frameRaw;
            original=graph.refs.get(nodeId);ownerSha=graph.backgroundOwnerSha;selectionRaw=graph.backgroundSelectionRaw;retainedAt=at;
            if(original==null)throw new IllegalArgumentException("readonly Flight source has no original target copy");
        }
        private synchronized void sealFrame(String raw){
            if(closed||frameRaw!=null||raw==null)throw new IllegalStateException("readonly Flight source already sealed or retired");
            frameRaw=raw;
        }
        private synchronized FlightObservationSnapshot copyForRead(){
            if(closed||frameRaw==null)throw new IllegalStateException("readonly Flight source is not live and sealed");
            Graph copy=graph.copyForAction(nodeId,null);
            try{return new FlightObservationSnapshot(service,web,background,scope,authorization,frame,copy,nodeId,targetPath,retainedAt,frameRaw);}
            catch(RuntimeException failure){copy.close();throw failure;}
        }
        @Override public synchronized void close(){if(closed)return;closed=true;graph.close();}
    }

    public interface ObservationCallback {
        void onObservation(PhoneObservation value); void onError(String error);
        // Old consumers remain compatible. The callable contains pure bounded values only.
        default void onDiagnostic(java.util.concurrent.Callable<String> snapshot) {}
    }
    public interface Cancellation { boolean isCancelled(); }
    public interface ActionCallback { void onResult(ActionOutcome result); }
    public static final class ActionOutcome {
        public final boolean accepted, dispatched, stale;
        public final String detail;
        public final AppCatalogueRanker.Page appCatalogue;
        public final JSONObject qualificationScope;
        public final JSONObject taskAuthorization;
        public final JSONObject backgroundSession;
        public final JSONObject imeSubmit;
        public final JSONObject fixedIntent;
        public final JSONObject toolChild;
        public final JSONObject actionExecution;
        ActionOutcome(boolean accepted,boolean dispatched,boolean stale,String detail) {
            this(accepted,dispatched,stale,detail,null);
        }
        ActionOutcome(boolean accepted,boolean dispatched,boolean stale,String detail,AppCatalogueRanker.Page appCatalogue) {
            this(accepted,dispatched,stale,detail,appCatalogue,null,null,null,null);
        }
        private ActionOutcome(boolean accepted,boolean dispatched,boolean stale,String detail,AppCatalogueRanker.Page appCatalogue,JSONObject scope,JSONObject authorization,JSONObject background,JSONObject imeSubmit){
            this(accepted,dispatched,stale,detail,appCatalogue,scope,authorization,background,imeSubmit,null);
        }
        private ActionOutcome(boolean accepted,boolean dispatched,boolean stale,String detail,AppCatalogueRanker.Page appCatalogue,JSONObject scope,JSONObject authorization,JSONObject background,JSONObject imeSubmit,JSONObject fixedIntent){
            this(accepted,dispatched,stale,detail,appCatalogue,scope,authorization,background,imeSubmit,fixedIntent,null);
        }
        private ActionOutcome(boolean accepted,boolean dispatched,boolean stale,String detail,AppCatalogueRanker.Page appCatalogue,JSONObject scope,JSONObject authorization,JSONObject background,JSONObject imeSubmit,JSONObject fixedIntent,JSONObject toolChild){
            this(accepted,dispatched,stale,detail,appCatalogue,scope,authorization,background,imeSubmit,fixedIntent,toolChild,null);
        }
        private ActionOutcome(boolean accepted,boolean dispatched,boolean stale,String detail,AppCatalogueRanker.Page appCatalogue,JSONObject scope,JSONObject authorization,JSONObject background,JSONObject imeSubmit,JSONObject fixedIntent,JSONObject toolChild,JSONObject actionExecution){
            this.accepted=accepted;this.dispatched=dispatched;this.stale=stale;this.detail=detail;
            this.appCatalogue=appCatalogue;this.qualificationScope=scope;this.taskAuthorization=authorization;this.backgroundSession=background;this.imeSubmit=imeSubmit;this.fixedIntent=fixedIntent;
            this.toolChild=toolChild;this.actionExecution=actionExecution;
        }
        ActionOutcome withScope(JSONObject scope){return new ActionOutcome(accepted,dispatched,stale,detail,appCatalogue,scope,taskAuthorization,backgroundSession,imeSubmit,fixedIntent,toolChild,actionExecution);
        }
        ActionOutcome withAuthorization(JSONObject authorization){return new ActionOutcome(accepted,dispatched,stale,detail,appCatalogue,qualificationScope,authorization,backgroundSession,imeSubmit,fixedIntent,toolChild,actionExecution);}
        ActionOutcome withBackground(JSONObject background){return new ActionOutcome(accepted,dispatched,stale,detail,appCatalogue,qualificationScope,taskAuthorization,background,imeSubmit,fixedIntent,toolChild,actionExecution);}
        ActionOutcome withSubmit(JSONObject value){return new ActionOutcome(accepted,dispatched,stale,detail,appCatalogue,qualificationScope,taskAuthorization,backgroundSession,value,fixedIntent,toolChild,actionExecution);}
        ActionOutcome withFixedIntent(JSONObject value){return new ActionOutcome(accepted,dispatched,stale,detail,appCatalogue,qualificationScope,taskAuthorization,backgroundSession,imeSubmit,value,toolChild,actionExecution);}
        ActionOutcome withToolChild(JSONObject value){return new ActionOutcome(accepted,dispatched,stale,detail,appCatalogue,qualificationScope,taskAuthorization,backgroundSession,imeSubmit,fixedIntent,value,actionExecution);}
        ActionOutcome withActionExecution(JSONObject value){return new ActionOutcome(accepted,dispatched,stale,detail,appCatalogue,qualificationScope,taskAuthorization,backgroundSession,imeSubmit,fixedIntent,toolChild,value);}
    }
    private static volatile HeptaAccessibilityService live;
    public static HeptaAccessibilityService connected() { return live; }
    // UI observers only. Task admission always reads the current service again.
    private static final java.util.Set<Runnable> connectionListeners=new java.util.concurrent.CopyOnWriteArraySet<Runnable>();
    static void addConnectionListener(Runnable listener){if(listener==null)throw new NullPointerException("listener");connectionListeners.add(listener);}
    static void removeConnectionListener(Runnable listener){connectionListeners.remove(listener);}
    private void publishConnectionChange(){for(Runnable listener:connectionListeners)main.post(listener);}
    private final Handler main=new Handler(Looper.getMainLooper());
    private volatile String lease;
    private QualificationScopeConfig.Bound taskScope;
    private TaskAuthorization.Gate taskAuthorization;
    private NotesTaskPhaseGuard taskNotesPhase;
    private CalculatorTaskInputGuard taskCalculatorInput;
    private BackgroundSession taskBackground;
    private WebFlightSession taskWeb;
    private SubmitAttemptGuard taskSubmitAttempts;
    private FixedIntentAttemptGuard taskFixedIntentAttempts;
    private final java.util.concurrent.ExecutorService backgroundIo=java.util.concurrent.Executors.newSingleThreadExecutor();
    // Read/copy/encode work must not block the main-looper deadline or cancellation callback.
    // This queue is separate from the broker queue so a slow Android read cannot delay cleanup.
    private static final java.util.concurrent.ExecutorService observationIo=java.util.concurrent.Executors.newSingleThreadExecutor();
    private static final java.util.concurrent.atomic.AtomicBoolean observationIoBusy=new java.util.concurrent.atomic.AtomicBoolean();
    // Separate, process-wide capacity: timeout retires authority, never frees a blocked action.
    private static final java.util.concurrent.ExecutorService actionIo=java.util.concurrent.Executors.newSingleThreadExecutor();
    private static final ActionExecutionState.Slot actionSlot=new ActionExecutionState.Slot();
    private volatile ActionWork activeAction;
    private volatile ActionExecutionState lastActionExecution;
    private static final TaskCancellationQueue nativeCancellationQueue=TaskCancellationQueue.processQueue();
    private Runnable stopListener;
    private LocalTaskController ownedController;
    private long lastScreenshotAt;
    private boolean capturePending;
    private long captureSerial;
    private volatile ObservationRequest activeObservation;
    private volatile PhoneObservation current;
    private Graph currentGraph;
    private Bitmap currentBitmap;
    private static final long MAX_OBSERVATION_AGE_MS=90000;
    // Bounded across the whole selected tree, including structural/nonvisible
    // nodes. A real browser snapshot had 975 nodes before its deeper controls.
    // Output remains independently bounded and native exact-token admission is unchanged.
    private static final int MAX_NODES=128, MAX_VISITED=1536, MAX_CHARACTERS=6144;
    // Private native evidence may retain a complete bounded card/header graph.
    // The model still receives only the current native provider action domain.
    private static final int NATIVE_APP_MAX_NODES=512;
    // Complete bounded evidence for an already bound helper lease. This does not
    // enlarge generic app actions or the model's permitted target set.
    private static final int WEB_MAX_NODES=512, WEB_MAX_CHARACTERS=32768;
    private final Map<String,String> launchable=new java.util.concurrent.ConcurrentHashMap<String,String>();
    private AppCatalogueRanker appDiscovery;

    @Override protected void onServiceConnected() {
        AccessibilityServiceInfo info=getServiceInfo();
        info.eventTypes=AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED|AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED
                |AccessibilityEvent.TYPE_WINDOWS_CHANGED
                |AccessibilityEvent.TYPE_VIEW_SCROLLED|AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED|AccessibilityEvent.TYPE_VIEW_FOCUSED;
        info.feedbackType=AccessibilityServiceInfo.FEEDBACK_GENERIC;
        info.flags|=AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS|AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS;
        info.notificationTimeout=80;setServiceInfo(info);refreshApps();live=this;publishConnectionChange();
    }
    @Override public void onAccessibilityEvent(AccessibilityEvent event) {
        // API 30..32 cannot identify the event display; conservatively invalidate the pending sample.
        noteObservationEvent(android.os.Build.VERSION.SDK_INT>=33?event.getDisplayId():-1);
    }
    @Override public void onInterrupt() {
        requestStop();
        if(activeObservation!=null)failObservation(activeObservation,"无障碍服务已中断");
    }
    @Override public void onDestroy() {
        ActionWork action=activeAction;if(action!=null)action.state.retire("service_destroyed");
        LocalTaskController controller; synchronized(this){controller=ownedController;}
        if(controller!=null)controller.close();
        if(taskWeb!=null)taskWeb.serviceRetired();
        requestStop();
        if(activeObservation!=null)failObservation(activeObservation,"无障碍服务已断开");
        // The process-wide read worker remains occupied until any in-flight Binder call really exits.
        // A replacement service instance cannot create a second queue around a stalled old read.
        if(live==this){live=null;publishConnectionChange();}clearSnapshot();backgroundIo.shutdown();super.onDestroy();
    }
    /** Service-owned session survives Activity recreation. The controller stays injectable. */
    public synchronized LocalTaskController taskController(LocalInference inference){
        if(ownedController==null)ownedController=new LocalTaskController(this,inference);
        return ownedController;
    }
    public synchronized LocalTaskController taskController(LocalModelEngine engine){
        return taskController(new EngineInferenceAdapter(engine));
    }
    /** Administrative retirement only; no action, inference, capture or old task is restarted. */
    synchronized boolean recoveryControllerIdle(LocalTaskController expected){
        if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("recovery service check must run on main thread");
        return live==this&&ownedController==expected&&(expected==null||!expected.isRunning())
                &&activeObservation==null&&!capturePending&&!observationReadWorkPending()&&!actionWorkPending()&&!nativeCancellationWorkPending()
                &&(taskBackground==null||taskBackground.released())&&(taskWeb==null||taskWeb.released())
                &&(lease==null||(expected!=null&&lease.equals(expected.currentTaskId())));
    }
    synchronized void retireControllerAfterAcknowledgement(LocalTaskController expected,
            RecoveryJournalTransaction.Proof proof){
        if(proof==null||!recoveryControllerIdle(expected))throw new IllegalStateException("controller is not idle for acknowledgement");
        if(expected!=null){expected.setListener(null);expected.close();}
        if(taskAuthorization!=null)taskAuthorization.retire();taskAuthorization=null;
        if(taskNotesPhase!=null)taskNotesPhase.retire();taskNotesPhase=null;
        if(taskCalculatorInput!=null)taskCalculatorInput.retire();taskCalculatorInput=null;
        if(taskSubmitAttempts!=null)taskSubmitAttempts.retire();taskSubmitAttempts=null;
        if(taskFixedIntentAttempts!=null)taskFixedIntentAttempts.retire();taskFixedIntentAttempts=null;
        ownedController=null;lease=null;stopListener=null;appDiscovery=null;taskScope=null;taskBackground=null;taskWeb=null;clearSnapshot();
    }
    private void requestStop() { Runnable value; synchronized(this){value=stopListener;} if(value!=null)value.run(); }
    public synchronized boolean acquireTask(String taskId,Runnable onStop) {
        if(WebFlightSession.hasUnreleased(this))return false;
        synchronized(nativeCancellationQueue.admissionMonitor()){
            if(lease!=null || live!=this||observationReadWorkPending()||actionWorkPending()||nativeCancellationWorkPending())return false;taskWeb=null;lease=taskId;stopListener=onStop;appDiscovery=null;taskScope=null;taskAuthorization=null;taskNotesPhase=null;taskCalculatorInput=null;taskBackground=null;taskSubmitAttempts=null;taskFixedIntentAttempts=null;return true;
        }
    }
    public synchronized void releaseTask(String taskId) { if(taskId.equals(lease)){
        if(actionWorkPending()||nativeCancellationWorkPending())throw new IllegalStateException("动作或取消工作尚未真实退出，不能释放任务租约");
        if(taskBackground!=null&&!taskBackground.released())throw new IllegalStateException("后台空间未核验释放，不能释放任务租约");
        if(taskWeb!=null&&!taskWeb.released())throw new IllegalStateException("网页工具未核验释放，不能释放任务租约");
        taskWeb=null;
        if(taskNotesPhase!=null)taskNotesPhase.retire();taskNotesPhase=null;
        if(taskCalculatorInput!=null)taskCalculatorInput.retire();taskCalculatorInput=null;
        if(taskAuthorization!=null)taskAuthorization.retire();if(taskSubmitAttempts!=null)taskSubmitAttempts.retire();taskSubmitAttempts=null;if(taskFixedIntentAttempts!=null)taskFixedIntentAttempts.retire();taskFixedIntentAttempts=null;taskAuthorization=null;lease=null;stopListener=null;appDiscovery=null;taskScope=null;taskBackground=null;} }
    synchronized void bindSubmitAttempts(String taskId,SubmitAttemptGuard attempts){
        if(!owns(taskId)||taskScope==null||taskAuthorization==null||taskSubmitAttempts!=null||attempts==null||!taskId.equals(attempts.taskId))
            throw new IllegalStateException("submit ledger requires the current bound task");
        taskSubmitAttempts=attempts;
    }
    synchronized void bindFixedIntentAttempts(String taskId,FixedIntentAttemptGuard attempts){
        if(!owns(taskId)||taskScope==null||taskAuthorization==null||taskFixedIntentAttempts!=null||attempts==null||!taskId.equals(attempts.taskId))
            throw new IllegalStateException("fixed intent ledger requires the current bound task");
        taskFixedIntentAttempts=attempts;
    }
    private synchronized FixedIntentAttemptGuard fixedIntentsFor(String taskId){
        if(!owns(taskId)||taskFixedIntentAttempts==null||!taskId.equals(taskFixedIntentAttempts.taskId))throw new IllegalStateException("fixed intent ledger unavailable");
        return taskFixedIntentAttempts;
    }
    java.util.Map<String,org.trillionnium.hepta.background.FixedIntentTarget> fixedIntentTargets(String taskId,TaskAuthorization.Frame authorization){
        QualificationScopeConfig.Bound scope=scopeFor(taskId);scope.verifyUnchanged();
        TaskAuthorization.require(authorization!=null&&taskId.equals(authorization.taskId),"fixed intent task differs");
        BackgroundSession background=backgroundFor(taskId);FixedIntentAttemptGuard ledger=fixedIntentsFor(taskId);
        java.util.Map<String,org.trillionnium.hepta.background.FixedIntentTarget> targets=new java.util.TreeMap<String,org.trillionnium.hepta.background.FixedIntentTarget>();
        // Legacy qualification fixtures never acquire a new effect from this feature.
        if(scope.config!=null)return targets;
        for(String action:new String[]{"notes.create","web.search"}){
            if(!authorization.allows(action)||!ledger.available(action))continue;
            org.trillionnium.hepta.background.FixedIntentTools.Profile profile=org.trillionnium.hepta.background.FixedIntentTools.forAction(action);
            if(background!=null&&!background.allows(profile.packageName))continue;
            try{targets.put(action,org.trillionnium.hepta.background.FixedIntentDispatch.inspect(this,android.os.Process.myUid(),action));}
            catch(Exception unavailable){/* Missing/export/permission/filter failures expose no tool authority. */}
        }
        QualificationScope.require(ownsScope(taskId,scope)&&ownsBackground(taskId,background),"fixed intent publication lease retired");
        return targets;
    }
    private synchronized SubmitAttemptGuard submitFor(String taskId){
        if(!owns(taskId)||taskSubmitAttempts==null||!taskId.equals(taskSubmitAttempts.taskId))
            throw new IllegalStateException("submit ledger unavailable or retired");
        return taskSubmitAttempts;
    }
    private synchronized boolean submitAvailable(String pkg,String textSha){
        return taskSubmitAttempts!=null&&owns(taskSubmitAttempts.taskId)&&taskSubmitAttempts.available(pkg,textSha);
    }
    private synchronized boolean owns(String taskId) { return taskId.equals(lease) && live==this; }
    private boolean locked() { KeyguardManager value=(KeyguardManager)getSystemService(KEYGUARD_SERVICE);return value!=null&&value.isKeyguardLocked(); }
    private int rotation(int displayId) {
        DisplayManager manager=(DisplayManager)getSystemService(DISPLAY_SERVICE);
        Display display=manager==null?null:manager.getDisplay(displayId);
        if(display==null||!display.isValid())throw new IllegalStateException("目标屏幕已不可用");return display.getRotation();
    }
    synchronized void bindWebFlightSession(String taskId,TaskAuthorization.Gate auth,WebFlightSession web){
        TaskAuthorization.require(ownsAuthorization(taskId,auth)&&taskBackground!=null&&taskWeb==null
                &&web!=null&&taskId.equals(web.taskId)&&web.authorization==auth,"web session does not belong to current task/background authority");
        taskWeb=web;
    }
    synchronized void acceptWebReconciliation(WebFlightSession.Cleanup proof)throws Exception{
        if(ownedController!=null&&ownedController.isRunning())throw new IllegalStateException("控制器尚未停止");
        if(taskWeb!=null)taskWeb.acceptReconciliation(proof);
    }
    synchronized void bindBackgroundSession(String taskId,BackgroundSession background){
        QualificationScope.require(owns(taskId)&&taskScope!=null&&!taskScope.restricted()&&taskBackground==null
                &&background!=null&&taskId.equals(background.taskId),"background lease requires an unscoped current task");
        taskScope.verifyUnchanged();taskBackground=background;
    }
    private synchronized BackgroundSession backgroundFor(String taskId){
        if(!owns(taskId))throw new IllegalStateException("任务已停止");return taskBackground;
    }
    private synchronized BackgroundSession currentBackground(){return taskBackground;}
    private synchronized boolean ownsBackground(String id,BackgroundSession background){return owns(id)&&taskBackground==background;}
    JSONObject backgroundEvidence(String id){BackgroundSession background=backgroundFor(id);return background==null?null:background.evidence();}
    synchronized void acceptBackgroundReconciliation(JSONObject proof)throws Exception{
        if(ownedController!=null&&ownedController.isRunning())throw new IllegalStateException("后台控制器尚未停止");
        if(taskBackground!=null)taskBackground.acceptReconciliation(proof);
    }
    /** Public Android client-cache invalidation only. It neither resets the app's
     * provider nor grants a fresh body/window proof; the next ordinary observation
     * must reacquire and validate its own complete graph on the existing worker. */
    JSONObject resetNotesClientCache(String id,TaskAuthorization.Gate auth,PhoneObservation expected)throws Exception{
        requireTaskAuthorization(id,auth);requireBackgroundObservation(id,expected);
        BackgroundSession background=backgroundFor(id);
        if(background==null||!background.selection.allowedPackages.equals(java.util.Collections.singletonList(NotesCompletionEvidence.NOTES))
                ||!NotesCompletionEvidence.NOTES.equals(expected.packageName)||!notesTaskPhaseFor(id,auth).supported())
            throw new IllegalStateException("Notes cache reset requires the current selected Notes task");
        if(observationReadWorkPending()||actionWorkPending())
            throw new IllegalStateException("Notes cache reset cannot overlap an unfinished observation or action");
        background.requireActive();
        boolean supported=android.os.Build.VERSION.SDK_INT>=33;
        boolean cleared=supported&&clearCache();
        requireTaskAuthorization(id,auth);background.requireActive();
        if(!ownsBackground(id,background))throw new IllegalStateException("Notes background lease changed during cache reset");
        return new JSONObject().put("schema","hepta.notes-client-cache-reset.v1").put("task_id",id)
                .put("authorization_sha256",auth.authorization.sha256).put("display_id",background.displayId())
                .put("background_generation",background.generation).put("prior_observation_id",expected.id)
                .put("prior_window_id",expected.windowId).put("api33_supported",supported).put("clear_cache_returned",cleared)
                .put("cache_scope","this_service_android_client_only").put("provider_cache_reset",false)
                .put("body_verified_by_reset",false).put("action_dispatched",false);
    }
    void verifyBackgroundRemote(String id)throws Exception{BackgroundSession background=backgroundFor(id);if(background!=null)background.verifyRemote();}
    void requireBackgroundObservation(String id,PhoneObservation observed){
        BackgroundSession background=backgroundFor(id);
        if(background==null){if(observed.backgroundGeneration!=null)throw new IllegalStateException("前台任务收到了后台观察");return;}
        background.requireActive();
        if(!background.generation.equals(observed.backgroundGeneration)||observed.windowMetadata.displayId==null
                ||background.displayId()!=observed.windowMetadata.displayId.intValue()||!background.allows(observed.packageName))
            throw new IllegalStateException("观察不属于本次后台屏幕与应用范围");
        try{
            JSONObject selected=observed.backgroundSelectionEvidence();
            if(selected==null||!WebEvidenceReceipt.same(selected,background.selection.json())
                    ||!background.selection.initialPackage.equals(observed.backgroundBootstrapPackage)
                    ||!background.selection.allowedPackages.equals(observed.backgroundAllowedPackages))
                throw new IllegalStateException("观察中的原始应用选择与当前后台租约不同");
        }catch(Exception invalid){throw new IllegalStateException("后台选择来源无法复核",invalid);}
    }


    private void refreshApps() {
        launchable.clear();Intent query=new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        for(ResolveInfo info:getPackageManager().queryIntentActivities(query,0)) {
            if(info.activityInfo!=null && info.activityInfo.exported && info.activityInfo.enabled)
                launchable.put(info.activityInfo.packageName,String.valueOf(info.loadLabel(getPackageManager())));
        }
    }
    /** Snapshot only installed launcher entries; model searches cannot add entries. */
    public AppCatalogueRanker.Page appCatalogue(String taskId,String instruction) {
        final QualificationScopeConfig.Bound scope=scopeFor(taskId);
        final BackgroundSession background=backgroundFor(taskId);
        scope.verifyUnchanged();refreshApps();
        Map<String,String> available=new HashMap<String,String>(launchable);
        // The immutable catalogue is filtered before ranking/pagination (93cbeb scope fix).
        java.util.Iterator<Map.Entry<String,String>> entries=available.entrySet().iterator();
        while(entries.hasNext()){
            String pkg=entries.next().getKey();
            if((scope.config!=null&&!scope.config.allows(pkg))||(background!=null&&!background.allows(pkg)))entries.remove();
        }
        AppCatalogueRanker snapshot=new AppCatalogueRanker(available,instruction);
        synchronized(this){
            QualificationScope.require(ownsScope(taskId,scope)&&ownsBackground(taskId,background),"task lease retired before app catalogue publication");
            scope.requireReady();appDiscovery=snapshot;
        }
        AppCatalogueRanker.Page initial=snapshot.search("",0);authorizationFor(taskId).bindCatalogue(initial);return initial;
    }

    private String diagnosticTask;private int diagnosticRequests;
    private synchronized ObservationDiagnostics observationDiagnostic(ObservationRequest request){
        BackgroundSession background=request.background;
        if(background==null||!owns(request.taskId)||!request.taskId.equals(background.taskId))return null;
        BackgroundTaskTarget target=background.selection.taskTarget;
        if(target==null||target.nativeGoal==null||!target.explicitSelection
                ||!BackgroundTaskTarget.NATIVE_APP.equals(target.route)
                ||!target.ownerSha256.equals(background.ownerSha256)
                ||!target.nativeGoal.ownerSha256.equals(background.ownerSha256)
                ||!target.nativeGoal.packageName.equals(target.packageName)
                ||!target.packageName.equals(background.selection.initialPackage)
                ||!background.selection.allowedPackages.equals(java.util.Collections.singletonList(target.packageName)))return null;
        if(!request.taskId.equals(diagnosticTask)){diagnosticTask=request.taskId;diagnosticRequests=0;}
        if(diagnosticRequests>=ObservationDiagnostics.MAX_RECORDS)return null;
        try{return new ObservationDiagnostics(request.taskId,UUID.randomUUID().toString().replace("-",""),
                background.ownerSha256,target.packageName,background.generation,request.displayId,++diagnosticRequests,request.started,request.deadline);}
        catch(RuntimeException unavailable){return null;}
    }
    /** Static: it cannot capture the Service, request, Graph, node or Bitmap. */
    private static final class DiagnosticSnapshot implements java.util.concurrent.Callable<String> {
        private final ObservationDiagnostics values;
        DiagnosticSnapshot(ObservationDiagnostics values){this.values=values;}
        @Override public String call(){
            String raw=new JSONObject(values.snapshot(SystemClock.elapsedRealtime())).toString();
            if(raw.getBytes(StandardCharsets.UTF_8).length>ObservationDiagnostics.MAX_JSON_BYTES)
                throw new IllegalStateException("bounded observation diagnostic exceeded");
            return raw;
        }
    }
    /** Each observation owns its samples/capture and the caller's original deadline. */
    private static final class ObservationRequest {
        final String taskId;final File directory;final ObservationCallback callback;final Cancellation cancel;
        final ObservationStabilityGate gate;final long started,deadline;final BackgroundSession background;final int displayId;
        Graph captured;long token;int intervalRetries;boolean shotPending,nativeSample;
        ObservationDiagnostics trace;
        volatile boolean finished;
        volatile long events,unknownEvents;
        private String phase="queued";private long phaseAt;
        ObservationRequest(String taskId,File directory,ObservationCallback callback,Cancellation cancel,long deadline,BackgroundSession background){
            this.taskId=taskId;this.directory=directory;this.callback=callback;this.cancel=cancel;this.background=background;
            this.started=SystemClock.elapsedRealtime();this.deadline=deadline;this.phaseAt=started;
            this.displayId=background==null?Display.DEFAULT_DISPLAY:background.displayId();
            this.gate=new ObservationStabilityGate(started,deadline);
        }
        synchronized void phase(String value){if(!finished){phase=value;phaseAt=SystemClock.elapsedRealtime();if(trace!=null)trace.phase(value,phaseAt);}}
        void note(ObservationDiagnostics.Event event){if(trace!=null)trace.note(event);}
        void worker(boolean active){if(trace!=null)trace.worker(active);}
        void graph(String stage,Graph graph){
            if(trace==null||graph==null||graph.diagnosticStamp==null)return;
            ObservationDiagnostics.GraphStamp stamp=graph.diagnosticStamp;
            if(!trace.packageName.equals(stamp.packageName)||!trace.generation.equals(stamp.generation)
                    ||trace.displayId!=stamp.displayId||!trace.ownerSha.equals(stamp.ownerSha))return;
            String key=sha((graph.packageName+"|"+graph.windowId+"|"+graph.rotation+"|"+graph.bounds+"|"+graph.digest+"|"+graph.truncated).getBytes(StandardCharsets.UTF_8));
            trace.graph(stage,key,stamp.appTree,stamp.state,stamp.window,graph.truncated,SystemClock.elapsedRealtime());
        }
        synchronized String diagnostic(String reason){
            long now=SystemClock.elapsedRealtime();
            return reason+" [phase="+phase+",elapsed_ms="+Math.max(0,now-started)+",phase_ms="+Math.max(0,now-phaseAt)+"]";
        }
    }
    /** Worker input contains only copied values, never a borrowed node/graph/Rect. */
    private static final class CaptureIdentity {
        final ObservationStabilityGate.FrameKey frame;final int displayId;final String generation;
        final long capturedAt,events,unknownEvents;final boolean nativeRecheck;
        CaptureIdentity(Graph graph,long capturedAt,long events,long unknownEvents,boolean nativeRecheck){
            frame=frameKey(graph);displayId=graph.displayId;generation=graph.backgroundGeneration;
            this.capturedAt=capturedAt;this.events=events;this.unknownEvents=unknownEvents;this.nativeRecheck=nativeRecheck;
        }
        boolean matches(Graph graph){return displayId==graph.displayId&&java.util.Objects.equals(generation,graph.backgroundGeneration)
                &&frame.equals(frameKey(graph));}
    }
    private static final class ObservationAbandoned extends IllegalStateException {
        private static final long serialVersionUID=1L;
        ObservationAbandoned(){super("observation work retired or deadline reached");}
    }
    /** Exactly one owner at a time: worker -> posted main callback -> current snapshot. */
    private static final class ObservationProduct {
        Bitmap bitmap;File path;String id,digest;boolean published,nativeGraphRechecked;long checkedEvents=-1;
        final long events,unknownEvents,capturedAt;
        ObservationProduct(CaptureIdentity identity){events=identity.events;unknownEvents=identity.unknownEvents;capturedAt=identity.capturedAt;}
        void close(){
            if(bitmap!=null){bitmap.recycle();bitmap=null;}
            // Best effort removal of this request's unpublished evidence, not a claim of durable deletion.
            if(path!=null&&!published){path.delete();path=null;}
        }
    }
    private void noteObservationEvent(int displayId){
        ObservationRequest request=activeObservation;
        if(request!=null&&!request.finished&&(displayId<0||displayId==request.displayId)){
            if(displayId<0)request.unknownEvents++;
            request.events++;request.note(displayId<0?ObservationDiagnostics.Event.EVENT_UNKNOWN:ObservationDiagnostics.Event.EVENT_TARGET);
        }
    }
    public void observe(final String taskId,final File evidenceDirectory,final Cancellation cancel,
                        final long deadline,final ObservationCallback callback) {
        final ObservationRequest request=new ObservationRequest(taskId,evidenceDirectory,callback,cancel,deadline,backgroundFor(taskId));
        request.trace=observationDiagnostic(request);
        if(request.trace!=null)try{callback.onDiagnostic(new DiagnosticSnapshot(request.trace));}
        catch(RuntimeException unavailable){/* Optional diagnostics grant no authority and do not replace the observation. */}
        main.post(new Runnable(){public void run(){
            if(activeObservation!=null){
                ObservationRequest old=activeObservation;
                if(!owns(old.taskId)||old.cancel.isCancelled())failObservation(old,"任务已经停止");
                else {callback.onError("已有屏幕观察尚未结束");return;}
            }
            if(capturePending){callback.onError("已有截图尚未结束");return;}
            if(observationIoBusy.get()){callback.onError(request.diagnostic("先前屏幕读取尚未退出，不堆积新观察"));return;}
            activeObservation=request;watchObservation(request);sampleObservation(request);
        }});
    }
    String observationTimeoutMessage(String taskId){
        ObservationRequest request=activeObservation;
        return request!=null&&request.taskId.equals(taskId)?request.diagnostic("系统屏幕观察超时")
                :"系统屏幕观察超时 [phase=callback_wait]";
    }
    boolean observationReadWorkPending(){return observationIoBusy.get();}
    private boolean observationActive(ObservationRequest request){
        if(request.finished||activeObservation!=request)return false;
        if(!request.gate.requestAlive(SystemClock.elapsedRealtime(),owns(request.taskId)&&!request.cancel.isCancelled())){
            failObservation(request,"任务停止或本次观察已超时");return false;
        }
        if(locked()){failObservation(request,"手机已锁定，请正常解锁后重新发起任务");return false;}
        return true;
    }
    /** Called only on main: unlike readGraph/PNG work, this watchdog never waits for the worker. */
    private void watchObservation(final ObservationRequest request){
        if(!observationActive(request))return;
        main.postDelayed(new Runnable(){public void run(){watchObservation(request);}},
                Math.max(1,Math.min(100,request.deadline-SystemClock.elapsedRealtime())));
    }
    /** Worker checks do not touch the main-owned stability gate or publish/retire any request. */
    private void requireObservationWork(ObservationRequest request){
        long now=SystemClock.elapsedRealtime();
        if(request.finished||activeObservation!=request||request.cancel.isCancelled()||!owns(request.taskId)
                ||!ownsBackground(request.taskId,request.background)||now<request.started||now>=request.deadline){
            request.note(ObservationDiagnostics.Event.WORKER_ABANDONED);throw new ObservationAbandoned();
        }
    }
    private GraphBudget observationBudget(final ObservationRequest request){
        return new GraphBudget(){public void check(){requireObservationWork(request);}};
    }
    private static ObservationStabilityGate.FrameKey frameKey(Graph graph){
        return new ObservationStabilityGate.FrameKey(graph.packageName,graph.windowId,graph.rotation,
                graph.bounds.left,graph.bounds.top,graph.bounds.right,graph.bounds.bottom,graph.digest,graph.truncated);
    }
    /** Read-only native evidence: no new traversal, IPC, action or deadline. */
    private boolean nativeObservationRecheckAllowed(ObservationRequest request,Graph graph){
        BackgroundSession background=request.background;
        if(graph==null||!graph.nativeObservationComplete||background==null||taskWeb!=null
                ||!ownsBackground(request.taskId,background)||!request.taskId.equals(background.taskId)
                ||request.displayId!=background.displayId()||graph.displayId!=request.displayId
                ||!background.generation.equals(graph.backgroundGeneration)
                ||!background.ownerSha256.equals(graph.backgroundOwnerSha)||graph.backgroundSelectionRaw==null)return false;
        BackgroundTaskTarget target=background.selection.taskTarget;
        return target!=null&&target.nativeGoal!=null&&target.explicitSelection
                &&BackgroundTaskTarget.NATIVE_APP.equals(target.route)
                &&background.ownerSha256.equals(target.ownerSha256)
                &&background.ownerSha256.equals(target.nativeGoal.ownerSha256)
                &&target.packageName.equals(target.nativeGoal.packageName)
                &&target.packageName.equals(background.selection.initialPackage)
                &&target.packageName.equals(graph.packageName)
                &&target.packageName.equals(graph.backgroundBootstrapPackage)
                &&background.selection.allowedPackages.equals(java.util.Collections.singletonList(target.packageName))
                &&background.selection.allowedPackages.equals(graph.backgroundAllowedPackages);
    }
    private void sampleObservation(final ObservationRequest request){
        if(!observationActive(request))return;
        if(!observationIoBusy.compareAndSet(false,true)){failObservation(request,"先前屏幕读取尚未退出");return;}
        request.note(ObservationDiagnostics.Event.SAMPLE_START);request.worker(true);request.phase("sample_graph");
        try{observationIo.execute(new Runnable(){public void run(){
            Graph graph=null;String error=null;final long unknownEvents=request.unknownEvents,events=request.events;
            try{
                requireObservationWork(request);
                try{graph=readGraph(observationBudget(request),request.background);}
                catch(NoActiveWindow busy){request.note(ObservationDiagnostics.Event.SAMPLE_NO_ROOT);}
                catch(StaleObservation busy){request.note(ObservationDiagnostics.Event.SAMPLE_STALE_ROOT);}
                request.graph("sample_graph",graph);requireObservationWork(request);
            }catch(Exception failure){request.note(ObservationDiagnostics.Event.SAMPLE_ERROR);error="无法读取当前活动窗口："+message(failure);}
            finally{request.worker(false);observationIoBusy.set(false);}
            final Graph sampled=graph;final String failure=error;
            boolean posted=false;
            try{posted=main.post(new Runnable(){public void run(){acceptSample(request,sampled,failure,events,unknownEvents);}});}
            finally{if(!posted&&sampled!=null)sampled.close();}
        }});}catch(RuntimeException unavailable){request.worker(false);observationIoBusy.set(false);failObservation(request,"屏幕观察队列不可用："+message(unavailable));}
    }
    private void acceptSample(final ObservationRequest request,Graph graph,String error,long events,long unknownEvents){
        try{
            if(!observationActive(request))return;
            if(error!=null){failObservation(request,error);return;}
            boolean nativeRecheck=nativeObservationRecheckAllowed(request,graph);
            if(events!=request.events||unknownEvents!=request.unknownEvents){
                if(nativeRecheck&&unknownEvents==request.unknownEvents){
                    // Target events request fresh evidence; the original gate still compares the whole observed graph.
                    request.note(ObservationDiagnostics.Event.SAMPLE_EVENT_RECHECKED);
                }else{
                    if(graph!=null){graph.close();graph=null;}request.gate.resetEvidence();nativeRecheck=false;
                    request.note(ObservationDiagnostics.Event.SAMPLE_EVENT_RESET);if(request.trace!=null)request.trace.reset();
                }
            }
            // Two complete native samples are required; an earlier legacy/incomplete sample cannot seed this path.
            if(nativeRecheck!=request.nativeSample){request.gate.resetEvidence();if(request.trace!=null)request.trace.reset();}
            request.nativeSample=nativeRecheck;
            long now=SystemClock.elapsedRealtime();
            ObservationStabilityGate.Result result=request.gate.sample(now,graph==null?null:frameKey(graph),true);
            if(graph==null&&request.trace!=null)request.trace.missingSample();
            request.note(ObservationDiagnostics.Event.valueOf("SAMPLE_"+result.name()));
            if(result==ObservationStabilityGate.Result.EXPIRED||result==ObservationStabilityGate.Result.CANCELLED){
                failObservation(request,"窗口仍在变化或没有活动窗口，未取得稳定观察");return;
            }
            long screenshotDelay=Math.max(0,400-(now-lastScreenshotAt));
            if(result==ObservationStabilityGate.Result.READY&&screenshotDelay==0){
                request.captured=graph;graph=null;captureObservation(request);return;
            }
            long delay=request.gate.nextSampleDelay(now);
            if(result==ObservationStabilityGate.Result.READY){request.note(ObservationDiagnostics.Event.SCREENSHOT_INTERVAL_WAIT);delay=Math.min(delay,screenshotDelay);}
            request.phase("sample_gap");
            main.postDelayed(new Runnable(){public void run(){sampleObservation(request);}},delay);
        }catch(Exception failure){failObservation(request,"无法接收当前活动窗口："+message(failure));}
        finally{if(graph!=null)graph.close();}
    }
    private void failObservation(ObservationRequest request,String error){
        if(request.finished)return;
        String diagnostic=request.diagnostic(error);
        request.note(ObservationDiagnostics.Event.REQUEST_ERROR);if(request.trace!=null)request.trace.finish("failed",SystemClock.elapsedRealtime());
        request.finished=true;request.gate.retire();
        if(request.shotPending&&captureSerial==request.token){capturePending=false;captureSerial++;}
        request.shotPending=false;
        if(request.captured!=null){request.captured.close();request.captured=null;}
        if(activeObservation==request)activeObservation=null;
        request.callback.onError(diagnostic);
    }
    private void retryObservation(final ObservationRequest request,long delay){
        if(request.captured!=null){request.captured.close();request.captured=null;}
        request.gate.resetEvidence();request.nativeSample=false;request.note(ObservationDiagnostics.Event.CAPTURE_RETRY);if(request.trace!=null)request.trace.reset();
        if(!observationActive(request))return;
        request.phase("retry_gap");
        // This never renews the fixed settling deadline or the original caller deadline.
        main.postDelayed(new Runnable(){public void run(){sampleObservation(request);}},
                Math.min(delay,request.gate.nextSampleDelay(SystemClock.elapsedRealtime())));
    }
    private void watchCapture(final ObservationRequest request,final long captureDeadline){
        if(request.finished||activeObservation!=request||!request.shotPending)return;
        if(!observationActive(request))return;
        if(SystemClock.elapsedRealtime()>=captureDeadline){failObservation(request,"系统截图回调超时");return;}
        main.postDelayed(new Runnable(){public void run(){watchCapture(request,captureDeadline);}},100);
    }
    private void captureObservation(final ObservationRequest request){
        if(!observationActive(request))return;
        if(capturePending){failObservation(request,"已有截图尚未结束");return;}
        // Non-native/unknown evidence keeps the original event fence. Native target events
        // require both post-capture whole-graph checks, including the graph after PNG persistence.
        final CaptureIdentity identity=new CaptureIdentity(request.captured,SystemClock.elapsedRealtime(),
                request.events,request.unknownEvents,request.nativeSample&&nativeObservationRecheckAllowed(request,request.captured));
        request.note(ObservationDiagnostics.Event.CAPTURE_START);
        capturePending=true;request.shotPending=true;lastScreenshotAt=identity.capturedAt;
        final long token=++captureSerial;request.token=token;request.phase("screenshot_callback");
        watchCapture(request,lastScreenshotAt+5000);
        try{takeScreenshot(identity.displayId,getMainExecutor(),new TakeScreenshotCallback(){
            @Override public void onFailure(int code){
                if(request.finished||activeObservation!=request||captureSerial!=token)return;
                capturePending=false;captureSerial++;request.shotPending=false;
                if(!observationActive(request))return;
                request.note(ObservationDiagnostics.Event.CAPTURE_CALLBACK_FAIL);
                if(code==ERROR_TAKE_SCREENSHOT_INTERVAL_TIME_SHORT&&request.intervalRetries++<1){
                    request.note(ObservationDiagnostics.Event.INTERVAL_RETRY);retryObservation(request,500);
                }
                else failObservation(request,"系统截图失败，错误码 "+code+"；不会绕过受保护画面");
            }
            @Override public void onSuccess(ScreenshotResult result){
                if(request.finished||activeObservation!=request||captureSerial!=token){result.getHardwareBuffer().close();return;}
                capturePending=false;captureSerial++;request.shotPending=false;
                if(!observationActive(request)){result.getHardwareBuffer().close();return;}
                request.note(ObservationDiagnostics.Event.CAPTURE_CALLBACK_OK);processScreenshot(request,identity,result);
            }
        });}catch(Exception error){failObservation(request,"系统截图不可用："+message(error));}
    }
    private void processScreenshot(final ObservationRequest request,final CaptureIdentity identity,final ScreenshotResult result){
        if(!observationIoBusy.compareAndSet(false,true)){
            result.getHardwareBuffer().close();failObservation(request,"先前屏幕读取尚未退出");return;
        }
        request.worker(true);
        try{observationIo.execute(new Runnable(){public void run(){
            final ObservationProduct product=new ObservationProduct(identity);Graph after=null;
            boolean copyEntered=false,retry=false;String error=null;
            try{
                requireObservationWork(request);request.phase("screenshot_copy");copyEntered=true;
                product.bitmap=copyScreenshot(result);requireObservationWork(request);
                request.phase("screenshot_graph");
                try{after=readGraph(observationBudget(request),request.background);}
                catch(NoActiveWindow busy){request.note(ObservationDiagnostics.Event.SCREENSHOT_GRAPH_MISSING);retry=true;}
                catch(StaleObservation busy){request.note(ObservationDiagnostics.Event.SCREENSHOT_GRAPH_STALE);retry=true;}
                request.graph("screenshot_graph",after);
                if(!retry&&!identity.matches(after)){request.note(ObservationDiagnostics.Event.SCREENSHOT_GRAPH_CHANGED);retry=true;}
                product.nativeGraphRechecked=!retry&&identity.nativeRecheck&&nativeObservationRecheckAllowed(request,after);
                if(after!=null){after.close();after=null;}
                if(!retry){
                    if(product.bitmap.getWidth()<1||product.bitmap.getHeight()<1||(long)product.bitmap.getWidth()*product.bitmap.getHeight()>16000000L)
                        throw new IllegalStateException("屏幕尺寸超出观察范围");
                    requireObservationWork(request);
                    if(!request.directory.isDirectory())throw new IllegalStateException("任务证据目录不存在");
                    product.id=UUID.randomUUID().toString().replace("-","");File path=new File(request.directory,product.id+".png");
                    if(!path.createNewFile())throw new IllegalStateException("观察标识重复");
                    product.path=path; // Only a file actually created by this request may be removed.
                    request.phase("png_encode");
                    try(FileOutputStream stream=new FileOutputStream(path)){
                        if(!product.bitmap.compress(Bitmap.CompressFormat.PNG,100,stream))throw new IllegalStateException("截图编码失败");
                        requireObservationWork(request);request.phase("png_fsync");stream.getFD().sync();
                    }
                    requireObservationWork(request);
                    path.setReadable(false,false);path.setReadable(true,true);path.setWritable(false,false);path.setWritable(true,true);
                    request.phase("png_hash");product.digest=fileSha256(path);requireObservationWork(request);
                    // Encoding/fsync/hash cannot turn a changed graph into a newly published observation.
                    request.phase("saved_graph");
                    // A later event cannot be credited to a graph whose read has already started.
                    product.checkedEvents=request.events;
                    try{after=readGraph(observationBudget(request),request.background);}
                    catch(NoActiveWindow busy){request.note(ObservationDiagnostics.Event.SAVED_GRAPH_MISSING);retry=true;}
                    catch(StaleObservation busy){request.note(ObservationDiagnostics.Event.SAVED_GRAPH_STALE);retry=true;}
                    request.graph("saved_graph",after);
                    if(!retry&&!identity.matches(after)){request.note(ObservationDiagnostics.Event.SAVED_GRAPH_CHANGED);retry=true;}
                    product.nativeGraphRechecked=product.nativeGraphRechecked&&!retry&&nativeObservationRecheckAllowed(request,after);
                }
                requireObservationWork(request);
            }catch(Exception failure){error="观察失败："+message(failure);}
            finally{
                if(!copyEntered)result.getHardwareBuffer().close();
                if(after!=null)after.close();request.worker(false);observationIoBusy.set(false);
            }
            final boolean resample=retry;final String failure=error;boolean posted=false;
            try{posted=main.post(new Runnable(){public void run(){acceptScreenshot(request,product,resample,failure);}});}
            finally{if(!posted)product.close();}
        }});}catch(RuntimeException unavailable){
            request.worker(false);observationIoBusy.set(false);result.getHardwareBuffer().close();failObservation(request,"屏幕观察队列不可用："+message(unavailable));
        }
    }
    private void acceptScreenshot(ObservationRequest request,ObservationProduct product,boolean retry,String error){
        try{
            if(!observationActive(request))return;
            if(error!=null){failObservation(request,error);return;}
            boolean eventsChanged=product.events!=request.events||product.unknownEvents!=request.unknownEvents;
            boolean eventsRechecked=eventsChanged&&product.nativeGraphRechecked
                    &&product.unknownEvents==request.unknownEvents&&product.checkedEvents==request.events
                    &&nativeObservationRecheckAllowed(request,request.captured);
            if(retry||(eventsChanged&&!eventsRechecked)){
                if(eventsChanged)request.note(ObservationDiagnostics.Event.CAPTURE_EVENT_RESET);
                retryObservation(request,200);return;
            }
            if(eventsRechecked)request.note(ObservationDiagnostics.Event.CAPTURE_EVENT_RECHECKED);
            request.phase("publish");
            Graph graph=request.captured;
            if(graph==null||product.bitmap==null||product.path==null||product.digest==null)
                throw new IllegalStateException("观察结果所有权不完整");
            if(!observationActive(request))return;
            PhoneObservation observation=new PhoneObservation(product.id,graph.packageName,product.capturedAt,
                    product.bitmap.getWidth(),product.bitmap.getHeight(),graph.rotation,graph.windowId,graph.bounds,product.path,product.digest,graph.digest,graph.state,graph.windowMetadata,graph.truncated,graph.rows,graph.backgroundGeneration,graph.backgroundBootstrapPackage,graph.backgroundAllowedPackages,graph.collectionStats,
                    graph.backgroundSelectionRaw==null?null:new JSONObject(graph.backgroundSelectionRaw),graph.backgroundOwnerSha);
            clearSnapshot();current=observation;currentGraph=graph;currentBitmap=product.bitmap;
            request.captured=null;product.bitmap=null;product.published=true;
            if(request.trace!=null)request.trace.published(observation.id,SystemClock.elapsedRealtime());
            request.finished=true;request.gate.retire();activeObservation=null;
            request.callback.onObservation(observation);
        }catch(Exception failure){failObservation(request,"观察发布失败："+message(failure));}
        finally{product.close();}
    }
    private static Bitmap copyScreenshot(ScreenshotResult result) {
        HardwareBuffer buffer=result.getHardwareBuffer();Bitmap wrapped=null;
        try{
            wrapped=Bitmap.wrapHardwareBuffer(buffer,result.getColorSpace());
            if(wrapped==null)throw new IllegalStateException("无法读取系统截图缓冲区");
            Bitmap copy=wrapped.copy(Bitmap.Config.ARGB_8888,false);
            if(copy==null)throw new IllegalStateException("无法复制系统截图");return copy;
        }finally{if(wrapped!=null)wrapped.recycle();buffer.close();}
    }
    private void clearSnapshot(){if(currentGraph!=null)currentGraph.close();if(currentBitmap!=null)currentBitmap.recycle();current=null;currentGraph=null;currentBitmap=null;}

    synchronized void bindQualificationScope(String taskId,QualificationScopeConfig.Bound scope){
        QualificationScope.require(owns(taskId)&&taskScope==null&&scope!=null&&taskId.equals(scope.taskId),"scope lease binding invalid");
        taskScope=scope;
    }
    synchronized TaskAuthorization.Gate bindTaskAuthorization(String taskId,TaskAuthorization authorization){
        TaskAuthorization.require(owns(taskId)&&taskAuthorization==null&&authorization!=null,"任务授权缺失、重复或租约不一致");
        taskAuthorization=authorization.bind(taskId);taskNotesPhase=new NotesTaskPhaseGuard(taskId,authorization);
        taskCalculatorInput=new CalculatorTaskInputGuard(taskId,authorization);return taskAuthorization;
    }
    synchronized NotesTaskPhaseGuard notesTaskPhaseFor(String id,TaskAuthorization.Gate auth){
        TaskAuthorization.require(ownsAuthorization(id,auth)&&taskNotesPhase!=null&&id.equals(taskNotesPhase.taskId)
                &&taskNotesPhase.authorization==auth.authorization,"任务阶段约束未绑定或已退休");return taskNotesPhase;
    }
    synchronized CalculatorTaskInputGuard calculatorInputFor(String id,TaskAuthorization.Gate auth){
        TaskAuthorization.require(ownsAuthorization(id,auth)&&taskCalculatorInput!=null&&id.equals(taskCalculatorInput.taskId)
                &&taskCalculatorInput.authorization==auth.authorization,"计算器输入约束未绑定或已退休");return taskCalculatorInput;
    }
    private synchronized TaskAuthorization.Gate authorizationFor(String taskId){
        TaskAuthorization.require(owns(taskId)&&taskAuthorization!=null&&taskId.equals(taskAuthorization.taskId),"任务授权未绑定");return taskAuthorization;
    }
    private synchronized boolean ownsAuthorization(String id,TaskAuthorization.Gate auth){return auth!=null&&owns(id)&&taskAuthorization==auth;}
    JSONObject taskAuthorizationEvidence(String id){return new JSONObject(authorizationFor(id).evidence());}
    void requireTaskAuthorization(String id,TaskAuthorization.Gate auth){
        TaskAuthorization.require(ownsAuthorization(id,auth),"观察任务授权已退休或被替换");auth.ready();
    }
    void requireAuthorizationObservation(String id,TaskAuthorization.Gate auth,PhoneObservation obs){
        requireTaskAuthorization(id,auth);auth.observed(obs.packageName,obs.id);
    }
    private void authorizationBeforeDispatch(String id,TaskAuthorization.Gate auth,ActionDecision action,String run){
        TaskAuthorization.require(ownsAuthorization(id,auth),"派发任务授权已退休或被替换");auth.check(action,run);
        if(action.toolChildOrigin!=null)action.toolChildOrigin.requireDispatch(id,auth.authorization.sha256,run,action);
        notesTaskPhaseFor(id,auth).requireCurrent(action);
        calculatorInputFor(id,auth).requireCurrent(action);
        WebFlightSession web=taskWeb;if(web!=null)web.requireDispatch(action,run);
    }
    private JSONObject callbackAuthorizationEvidence(TaskAuthorization.Gate auth,boolean current,boolean stopped){
        if(auth==null)return null;
        try{return new JSONObject(auth.evidence()).put("callback_lease_current",current).put("callback_cancelled",stopped);}
        catch(Exception error){throw new IllegalStateException(error);}
    }
    private synchronized QualificationScopeConfig.Bound scopeFor(String taskId){
        QualificationScope.require(owns(taskId)&&taskScope!=null&&taskId.equals(taskScope.taskId),"scope lease not bound");return taskScope;
    }
    JSONObject qualificationScopeEvidence(String taskId){return scopeFor(taskId).evidence();}
    private synchronized boolean ownsScope(String taskId,QualificationScopeConfig.Bound scope){
        return scope!=null&&owns(taskId)&&taskScope==scope;
    }
    private static JSONObject callbackScopeEvidence(String taskId,QualificationScopeConfig.Bound captured,boolean currentLease,boolean cancelled){
        try{
            JSONObject value=captured==null?new JSONObject().put("schema","hepta.qualification-task-scope.v1").put("task_id",taskId)
                    .put("expected_scope_sha256",JSONObject.NULL).put("actual_scope_sha256",JSONObject.NULL)
                    .put("scope_loaded",false).put("scope_refused",true).put("refusal","task scope unavailable at dispatch"):captured.evidence();
            return value.put("callback_lease_current",currentLease).put("callback_cancelled",cancelled);
        }catch(Exception error){throw new IllegalStateException("cannot encode captured action scope",error);}
    }
    void requireScopeObservation(String taskId,PhoneObservation observation){
        QualificationScopeConfig.Bound scope=scopeFor(taskId);
        try{
            scope.verifyUnchanged();if(scope.config==null)return;
            QualificationScope.require(observation!=null&&observation.windowId>=0&&scope.config.allows(observation.packageName),"observed package outside scope or unknown");
            QualificationScope.require(observation.windowMetadata!=null&&"observed".equals(observation.windowMetadata.status)
                    &&Integer.valueOf(AccessibilityWindowInfo.TYPE_APPLICATION).equals(observation.windowMetadata.type)
                    &&Integer.valueOf(Display.DEFAULT_DISPLAY).equals(observation.windowMetadata.displayId),"observed application window metadata unknown");
        }catch(Exception error){scope.refuse(message(error));throw new QualificationScope.Violation(message(error));}
    }
    /** Only freshness failures before an effect may request a new observation/model decision. */
    private static final class StaleObservation extends IllegalStateException {
        private static final long serialVersionUID=1L;
        StaleObservation(String detail){super("stale:"+detail);}
    }
    /** Rechecks the complete original scope immediately before dispatch, on the selected action thread. */
    private void scopeBeforeDispatch(String taskId,QualificationScopeConfig.Bound dispatchScope,PhoneObservation expected,ActionDecision action,AccessibilityNodeInfo node,boolean nodeRequired,ActionWork work){
        actionPhase(work,"scope_read");actionCheck(work);
        QualificationScopeConfig.Bound scope=scopeFor(taskId);
        QualificationScope.require(scope==dispatchScope,"dispatch scope was retired");
        AccessibilityNodeInfo root=null;AccessibilityWindowInfo window=null;
        try{
            scope.verifyUnchanged();
            backgroundBeforeDispatch(taskId,expected,action,node,nodeRequired,work);
            if(scope.config==null){
                scope.gate.check(action.action,action.packageName,null,null,null,false);
                QualificationScope.require(ownsScope(taskId,scope),"scope lease retired before dispatch");return;
            }
            root=getRootInActiveWindow();
            if(root!=null)window=root.getWindow();
            QualificationScope.Window frame=null;
            if(root!=null&&window!=null&&window.getId()==root.getWindowId()){
                Rect bounds=new Rect();root.getBoundsInScreen(bounds);
                frame=new QualificationScope.Window(string(root.getPackageName()),root.getWindowId(),window.getType(),window.getDisplayId(),
                        window.isActive(),root.isVisibleToUser()&&!bounds.isEmpty());
            }
            boolean refreshed=!nodeRequired||(node!=null&&refreshActionNode(work,node));
            String operation="click".equals(action.action)&&action.nodeId==null?"coordinate_click":action.action;
            scope.gate.check(operation,action.packageName,frame,!refreshed||node==null?null:string(node.getPackageName()),!refreshed||node==null?null:Integer.valueOf(node.getWindowId()),nodeRequired);
            if(nodeRequired){
                Graph selected=graphForAction(work);NodeRef ref=selected==null?null:selected.refs.get(action.nodeId);
                QualificationScope.require(ref!=null&&ref.node==node&&node.isVisibleToUser()&&node.isEnabled()
                        &&ref.signature.equals(nodeSignature(node,observedChildText(node,false,work==null?null:work.budget()))),"scope node changed before dispatch");
            }
            QualificationScope.require(frame!=null&&expected!=null&&frame.packageName.equals(expected.packageName)&&frame.windowId==expected.windowId,
                    "fresh scope window differs from bound observation");
            QualificationScope.require(ownsScope(taskId,scope),"scope lease retired before dispatch");
        }catch(StaleObservation changed){throw changed;}
        catch(Exception error){scope.refuse(message(error));throw new QualificationScope.Violation(message(error));}
        finally{if(window!=null)window.recycle();if(root!=null)root.recycle();}
    }
    private void backgroundBeforeDispatch(String taskId,PhoneObservation expected,ActionDecision action,AccessibilityNodeInfo node,boolean nodeRequired,ActionWork work){
        BackgroundSession background=backgroundFor(taskId);if(background==null)return;
        requireBackgroundObservation(taskId,expected);
        if("home".equals(action.action))throw new IllegalArgumentException("后台任务不提供 HOME，也不会回退到主屏导航");
        if("click".equals(action.action)&&action.nodeId==null)throw new IllegalArgumentException("后台任务只接受已观察节点动作，不派发坐标手势");
        if(!background.allows(action.packageName))throw new IllegalArgumentException("动作应用超出本次后台范围");
        AccessibilityNodeInfo root=null;AccessibilityWindowInfo window=null;
        try{
            root=selectedRoot(background,work==null?null:work.budget());window=root==null?null:root.getWindow();
            if(root==null||window==null||window.getDisplayId()!=background.displayId()
                    ||window.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION||root.getWindowId()!=expected.windowId
                    ||!expected.packageName.equals(string(root.getPackageName()))||!root.isVisibleToUser())
                throw new IllegalStateException("后台目标窗口已变化");
            if(nodeRequired){
                Graph selected=graphForAction(work);NodeRef ref=selected==null?null:selected.refs.get(action.nodeId);
                if(node==null||ref==null||ref.node!=node)throw new IllegalStateException("后台节点不属于本次观察");
                boolean refreshed=refreshActionNode(work,node);background.requireActive();
                if(!refreshed)throw new StaleObservation("后台节点已不可用，需重新观察");
                // Identity failures stay terminal, even when the same refresh also changes text.
                requireBackgroundNodeWindow(background,expected,node);
                if(!node.isVisibleToUser()||!node.isEnabled()
                        ||!ref.signature.equals(nodeSignature(node,observedChildText(node,true,work==null?null:work.budget()))))
                    throw new StaleObservation("后台节点内容已变化，需重新观察");
            }
            if(!ownsBackground(taskId,background))throw new IllegalStateException("后台任务租约已退休");
        }finally{if(window!=null)window.recycle();if(root!=null)root.recycle();}
    }
    private static void requireBackgroundNodeWindow(BackgroundSession background,PhoneObservation expected,AccessibilityNodeInfo node){
        AccessibilityWindowInfo window=null;
        try{
            background.requireActive();
            window=node.getWindow();
            if(window==null||window.getDisplayId()!=background.displayId()||window.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION
                    ||window.getId()!=expected.windowId||node.getWindowId()!=expected.windowId
                    ||!expected.packageName.equals(string(node.getPackageName()))||!background.allows(string(node.getPackageName())))
                throw new IllegalStateException("后台节点已移出绑定屏幕、窗口或应用");
        }finally{if(window!=null)window.recycle();}
    }
    private void scopeOpenIntent(String taskId,QualificationScopeConfig.Bound dispatchScope,String target,Intent launch){
        QualificationScopeConfig.Bound scope=scopeFor(taskId);QualificationScope.require(scope==dispatchScope,"dispatch scope was retired");if(scope.config==null)return;
        try{
            ResolveInfo resolved=getPackageManager().resolveActivity(launch,0);
            QualificationScope.require(launch.getComponent()!=null&&target.equals(launch.getComponent().getPackageName())
                    &&resolved!=null&&resolved.activityInfo!=null&&target.equals(resolved.activityInfo.packageName),"launch entry resolves outside scoped target");
        }catch(Exception error){scope.refuse(message(error));throw new QualificationScope.Violation(message(error));}
    }

    public void perform(final String taskId,final PhoneObservation expected,final ActionDecision decision,
                        final ObservedTargetLabels targets,final TaskAuthorization.Gate expectedAuthorization,final String modelRunId,
                        final Cancellation cancel,final ActionCallback callback){
        perform(taskId,expected,decision,targets,null,expectedAuthorization,modelRunId,cancel,callback);
    }
    public void perform(final String taskId,final PhoneObservation expected,final ActionDecision decision,
                        final ObservedTargetLabels targets,final org.trillionnium.hepta.background.FixedIntentTarget fixedTarget,
                        final TaskAuthorization.Gate expectedAuthorization,final String modelRunId,
                        final Cancellation cancel,final ActionCallback callback){
        perform(taskId,expected,decision,targets,fixedTarget,expectedAuthorization,modelRunId,
                SystemClock.elapsedRealtime()+8000,cancel,callback);
    }
    public void perform(final String taskId,final PhoneObservation expected,final ActionDecision decision,
                        final ObservedTargetLabels targets,final org.trillionnium.hepta.background.FixedIntentTarget fixedTarget,
                        final TaskAuthorization.Gate expectedAuthorization,final String modelRunId,final long deadline,
                        final Cancellation cancel,final ActionCallback callback){
        perform(taskId,expected,decision,targets,fixedTarget,expectedAuthorization,modelRunId,deadline,null,cancel,callback);
    }
    void perform(final String taskId,final PhoneObservation expected,final ActionDecision decision,
                        final ObservedTargetLabels targets,final org.trillionnium.hepta.background.FixedIntentTarget fixedTarget,
                        final TaskAuthorization.Gate expectedAuthorization,final String modelRunId,final long deadline,
                        final NativeAppSession.ActionGuard nativeGuard,final Cancellation cancel,final ActionCallback callback){
        final long queued=SystemClock.elapsedRealtime();
        // A late callback keeps the original task sources, never a newly admitted lease.
        final QualificationScopeConfig.Bound captured;final TaskAuthorization.Gate capturedAuthorization;final BackgroundSession capturedBackground;
        synchronized(this){captured=owns(taskId)?taskScope:null;capturedAuthorization=owns(taskId)?taskAuthorization:null;capturedBackground=owns(taskId)?taskBackground:null;}
        final ActionCallback boundCallback=new ActionCallback(){public void onResult(ActionOutcome result){
            callback.onResult(bindActionOutcome(taskId,decision,expectedAuthorization,cancel,captured,capturedAuthorization,capturedBackground,result));
        }};
        main.post(new Runnable(){public void run(){
            if(!ownsScope(taskId,captured)||!ownsAuthorization(taskId,capturedAuthorization)||capturedAuthorization!=expectedAuthorization
                    ||!ownsBackground(taskId,capturedBackground)||cancel.isCancelled()||SystemClock.elapsedRealtime()>=deadline){
                boundCallback.onResult(new ActionOutcome(false,false,false,"任务已停止、到期或作用范围未绑定"));return;
            }
            if(decision.toolChildOrigin!=null)try{
                decision.toolChildOrigin.enterService(taskId,capturedAuthorization.authorization.sha256,modelRunId,expected.id);
            }catch(Exception refused){boundCallback.onResult(new ActionOutcome(false,false,false,message(refused)));return;}
            // Preserve legacy foreground coordinates and unknown-window frames without inventing an ID.
            // Neither path is claimed as repaired by this worker; background never falls back to the main display.
            boolean legacyUnknownWindow=capturedBackground==null&&captured.config==null&&expected==current
                    &&currentGraph!=null&&currentGraph.windowId<0;
            if(("click".equals(decision.action)&&decision.nodeId==null)||legacyUnknownWindow){
                performOnAction(taskId,expected,decision,targets,fixedTarget,cancel,boundCallback,captured,capturedAuthorization,modelRunId,null);return;
            }
            Graph snapshot=null;
            try{
                if(expected!=current||currentGraph==null)throw new StaleObservation("观察标识已失效");
                // This lookup validates immutable in-memory evidence only; node refresh and live window reads stay on actionIo.
                WebFlightSession web=taskWeb;
                WebRegionNativeBridge region=web==null?null:web.nativeRegionForDispatch(decision,modelRunId,expected);
                snapshot=currentGraph.copyForAction(decision.nodeId,region);
                final ActionWork work=new ActionWork(taskId,expected,modelRunId,captured,capturedAuthorization,capturedBackground,cancel,snapshot,region,queued,deadline,nativeGuard);
                if(!actionSlot.acquire(work.state))throw new IllegalStateException("已有动作工作尚未真实退出");
                activeAction=work;lastActionExecution=work.state;snapshot=null;
                try{actionIo.execute(new Runnable(){public void run(){
                    ActionOutcome result=null;
                    final java.util.concurrent.atomic.AtomicReference<ActionOutcome> outcome=new java.util.concurrent.atomic.AtomicReference<ActionOutcome>();
                    try{
                        work.phase("worker_started");work.check();
                        performOnAction(taskId,expected,decision,targets,fixedTarget,cancel,new ActionCallback(){public void onResult(ActionOutcome value){
                            if(!outcome.compareAndSet(null,value))throw new IllegalStateException("动作产生重复回执");
                        }},captured,capturedAuthorization,modelRunId,work);
                        result=outcome.get();
                        if(result==null)throw new IllegalStateException("动作没有同步完成回执");
                        if(cancel.isCancelled()||SystemClock.elapsedRealtime()>=deadline||work.state.retired())
                            result=new ActionOutcome(false,result.dispatched,false,"动作已停止或到期；保留已经发生的派发，不重试",result.appCatalogue)
                                    .withSubmit(result.imeSubmit).withFixedIntent(result.fixedIntent);
                        result=bindActionOutcome(taskId,decision,expectedAuthorization,cancel,captured,capturedAuthorization,capturedBackground,result);
                    }catch(Exception failure){
                        result=new ActionOutcome(false,work.state.effectEntered(),false,"动作未得到完整确认；不重试："+message(failure));
                        try{result=bindActionOutcome(taskId,decision,expectedAuthorization,cancel,captured,capturedAuthorization,capturedBackground,result);}
                        catch(Exception unavailable){/* Missing scope evidence remains a hard consumer failure. */}
                    }finally{
                        // No shared currentGraph node is owned here. Never free capacity on logical cancellation.
                        work.graph.close();work.logMarker(work.state.drained());
                        if(activeAction==work)activeAction=null;actionSlot.release(work.state);
                    }
                    final ActionOutcome computed=result;
                    main.post(new Runnable(){public void run(){
                        // Delivery may be delayed by unrelated UI work. Recheck only captured identities and atomic flags.
                        boolean currentLease=work.currentLease(),stopped=cancel.isCancelled();
                        boolean allowed=work.state.publish(stopped,currentLease);
                        ActionOutcome delivered=allowed?computed:new ActionOutcome(false,computed.dispatched,false,
                                "任务已停止、到期或租约已退休；拒绝迟到回执，不重试",computed.appCatalogue)
                                .withScope(callbackFlags(computed.qualificationScope,currentLease,stopped))
                                .withAuthorization(callbackFlags(computed.taskAuthorization,currentLease,stopped))
                                .withBackground(computed.backgroundSession).withSubmit(computed.imeSubmit)
                                .withFixedIntent(computed.fixedIntent).withToolChild(computed.toolChild);
                        callback.onResult(delivered.withActionExecution(actionDiagnosticEvidence(work)));
                    }});
                }});}catch(java.util.concurrent.RejectedExecutionException rejected){
                    // execute() rejected before running: no worker, node read or effect is in flight.
                    work.state.retire("queue_rejected");work.graph.close();work.state.drained();
                    if(activeAction==work)activeAction=null;actionSlot.release(work.state);
                    work.state.publish(cancel.isCancelled(),work.currentLease());
                    boundCallback.onResult(new ActionOutcome(false,false,false,"动作队列未接受请求").withActionExecution(new JSONObject(work.state.evidence())));
                }catch(RuntimeException uncertainSubmission){
                    // Only definitive rejection proves no work started. An unexpected submit failure
                    // keeps the owned graph and process-wide slot fenced until a real worker finally.
                    work.state.retire("controller_abandoned");
                }
            }catch(Exception unavailable){
                if(snapshot!=null)snapshot.close();
                boundCallback.onResult(new ActionOutcome(false,false,unavailable instanceof StaleObservation,message(unavailable)));
            }
        }});
    }
    private ActionOutcome bindActionOutcome(String taskId,ActionDecision decision,TaskAuthorization.Gate expectedAuthorization,
            Cancellation cancel,QualificationScopeConfig.Bound captured,TaskAuthorization.Gate capturedAuthorization,
            BackgroundSession capturedBackground,ActionOutcome result){
        boolean currentLease=ownsScope(taskId,captured)&&ownsAuthorization(taskId,capturedAuthorization)
                &&capturedAuthorization==expectedAuthorization&&ownsBackground(taskId,capturedBackground),stopped=cancel.isCancelled();
        ActionOutcome delivered=currentLease&&!stopped?result:new ActionOutcome(false,result.dispatched,false,
                "任务已停止或租约已退休；保留已发生的派发，不接受迟到回执",result.appCatalogue)
                .withSubmit(result.imeSubmit).withFixedIntent(result.fixedIntent).withActionExecution(result.actionExecution);
        return delivered.withScope(callbackScopeEvidence(taskId,captured,currentLease,stopped))
                .withAuthorization(callbackAuthorizationEvidence(capturedAuthorization,currentLease,stopped))
                .withBackground(capturedBackground==null?null:capturedBackground.evidence())
                .withToolChild(decision.toolChildOrigin==null?null:new JSONObject(decision.toolChildOrigin.evidence()));
    }
    private static JSONObject callbackFlags(JSONObject captured,boolean currentLease,boolean stopped){
        if(captured==null)return null;
        try{return new JSONObject(captured.toString()).put("callback_lease_current",currentLease).put("callback_cancelled",stopped);}
        catch(Exception invalid){throw new IllegalStateException("captured callback evidence unavailable",invalid);}
    }
    boolean nativeCancellationWorkPending(){return nativeCancellationQueue.pending();}
    boolean requestNativeCancellation(TaskCancellationQueue.Ticket ticket,Runnable signal){
        if(ticket==null||ticket.taskId==null||!ticket.ownedBy(this))return false;
        return nativeCancellationQueue.request(ticket,new TaskCancellationQueue.Lease(){public boolean current(String taskId){
            // A retired service may cancel only its captured old lease. Never look up a replacement live service.
            return taskId.equals(lease);
        }},signal);
    }
    boolean actionWorkPending(){return actionSlot.pending();}
    void retireActionWork(String taskId,String reason){
        ActionWork work=activeAction;if(work!=null&&work.state.taskId.equals(taskId))work.state.retire(reason);
    }
    JSONObject actionExecutionEvidence(String taskId){
        ActionExecutionState value=lastActionExecution;
        return value==null||!value.taskId.equals(taskId)?null:new JSONObject(value.evidence());
    }
    private final class ActionWork {
        final ActionExecutionState state;final PhoneObservation expected;final Graph graph;final Cancellation cancel;
        final QualificationScopeConfig.Bound scope;final TaskAuthorization.Gate authorization;final BackgroundSession background;
        final WebRegionNativeBridge nativeRegion;
        String diagnosticFreshness;
        final NativeAppSession.ActionGuard nativeGuard;
        boolean nativeActionRevalidated;String nativeActionProof;
        ActionWork(String task,PhoneObservation expected,String run,QualificationScopeConfig.Bound scope,
                TaskAuthorization.Gate authorization,BackgroundSession background,Cancellation cancel,Graph graph,WebRegionNativeBridge nativeRegion,long queued,long deadline){
            this(task,expected,run,scope,authorization,background,cancel,graph,nativeRegion,queued,deadline,null);
        }
        ActionWork(String task,PhoneObservation expected,String run,QualificationScopeConfig.Bound scope,
                TaskAuthorization.Gate authorization,BackgroundSession background,Cancellation cancel,Graph graph,
                WebRegionNativeBridge nativeRegion,long queued,long deadline,NativeAppSession.ActionGuard nativeGuard){
            this.nativeGuard=nativeGuard;
            this.expected=expected;this.scope=scope;this.authorization=authorization;this.background=background;
            this.cancel=cancel;this.graph=graph;this.nativeRegion=nativeRegion;
            state=new ActionExecutionState(UUID.randomUUID().toString().replace("-",""),task,run,expected.id,
                    authorization.authorization.sha256,graph.windowId,graph.displayId,graph.backgroundGeneration,queued,deadline,
                    new ActionExecutionState.Clock(){public long elapsedRealtime(){return SystemClock.elapsedRealtime();}});
            state.phase("snapshot_cloned");
        }
        boolean currentLease(){
            return expected==current&&ownsScope(state.taskId,scope)&&ownsAuthorization(state.taskId,authorization)
                    &&ownsBackground(state.taskId,background)
                    &&(background==null?state.displayId==Display.DEFAULT_DISPLAY&&state.backgroundGeneration==null:
                    state.displayId==background.displayId()&&background.generation.equals(state.backgroundGeneration));
        }
        void check(){state.check(cancel.isCancelled(),currentLease());}
        GraphBudget budget(){return new GraphBudget(){public void check(){ActionWork.this.check();}};}
        void phase(String phase){check();logMarker(state.phase(phase));}
        void logMarker(Map<String,Object> marker){
            // Fixed phase/identity fields sampled inside the state lock. Log failure grants no authority.
            try{android.util.Log.i("HeptaAction",new JSONObject(marker).toString());}catch(RuntimeException unavailable){}
        }
        void enterEffect(){logMarker(state.enterEffect(cancel.isCancelled(),currentLease()));check();}
        void effectReturned(Boolean accepted){logMarker(state.effectReturned(accepted));}
    }
    private static void recordStaleDiagnostic(ActionWork work,Graph before,Graph after,String selectedId){
        if(work==null||work.background==null||work.diagnosticFreshness!=null)return;
        try{
            Map<String,Object> difference=ObservationDiagnostics.difference(before.diagnosticStamp,after.diagnosticStamp,selectedId);
            if(difference==null)return;
            Map<String,Object> operation=work.state.evidence();
            difference.put("task_id",operation.get("task_id"));difference.put("operation_id",operation.get("operation_id"));
            difference.put("model_run_id",operation.get("model_run_id"));difference.put("observation_id",operation.get("observation_id"));
            difference.put("guard_result","whole_graph_stale_rejected");difference.put("guard_changed",false);
            String raw=new JSONObject(difference).toString();
            if(raw.getBytes(StandardCharsets.UTF_8).length<=ObservationDiagnostics.MAX_JSON_BYTES)work.diagnosticFreshness=raw;
        }catch(RuntimeException unavailable){/* A diagnostic never changes the original refusal. */}
    }
    private static JSONObject actionDiagnosticEvidence(ActionWork work){
        JSONObject value=new JSONObject(work.state.evidence());
        if(work.diagnosticFreshness!=null)try{value.put("freshness_diagnostic",new JSONObject(work.diagnosticFreshness));}
        catch(Exception unavailable){/* Preserve the original execution receipt. */}
        if(work.nativeActionProof!=null)try{value.put("native_action_revalidation",new JSONObject(work.nativeActionProof));}
        catch(Exception unavailable){/* The original dispatch/retirement evidence remains authoritative. */}
        if(work.nativeGuard!=null)try{value.put("native_action_guard",new JSONObject(work.nativeGuard.evidence()));}
        catch(Exception unavailable){/* No new authority follows from missing audit metadata. */}
        return value;
    }
    private Cancellation actionCancellation(final ActionWork work,final Cancellation original){
        if(work==null)return original;
        return new Cancellation(){public boolean isCancelled(){
            try{work.check();return false;}catch(IllegalStateException unavailable){return true;}
        }};
    }
    private Graph graphForAction(ActionWork work){return work==null?currentGraph:work.graph;}
    private static void actionCheck(ActionWork work){if(work!=null)work.check();}
    private static void actionPhase(ActionWork work,String phase){if(work!=null)work.phase(phase);}
    private static void enterActionEffect(ActionWork work){if(work!=null)work.enterEffect();}
    private static void actionEffectReturned(ActionWork work,Boolean accepted){if(work!=null)work.effectReturned(accepted);}
    private boolean refreshActionNode(ActionWork work,AccessibilityNodeInfo node){
        actionPhase(work,"node_refresh");actionCheck(work);boolean refreshed=node.refresh();actionCheck(work);return refreshed;
    }
    private void afterActionDelay(final ActionWork work,Runnable completion,long delay){
        if(work==null){main.postDelayed(completion,delay);return;}
        long until=Math.min(work.state.deadlineElapsed,SystemClock.elapsedRealtime()+delay);
        try{
            work.phase("settle");
            while(SystemClock.elapsedRealtime()<until){work.check();SystemClock.sleep(Math.max(0,Math.min(50,until-SystemClock.elapsedRealtime())));}
            work.check();
        }catch(IllegalStateException retired){/* Deliver the original effect truth without reading retired nodes. */}
        completion.run();
    }
    private void executeActionIo(ActionWork work,Runnable action){if(work==null)backgroundIo.execute(action);else action.run();}
    private void deliverActionCallback(ActionWork work,Runnable callback){if(work==null)main.post(callback);else callback.run();}
    private static String targetBindingError(PhoneObservation expected,ActionDecision action,ObservedTargetLabels targets){
        // The label/id pair is the immutable prompt projection, never a live-tree substitution.
        if(expected==null||targets==null||!expected.id.equals(targets.observationId)||!expected.packageName.equals(targets.packageName))
            return "目标标签投影不属于本次观察";
        if(action.nodeId!=null&&!targets.matches(action.observationId,action.packageName,action.nodeId,action.nodeLabel))
            return "节点文字与标识不是本次观察提供的原始配对";
        return null;
    }
    private void requireNativeActionGuard(String task,PhoneObservation frame,ActionDecision action,ActionWork work)throws Exception{
        if(work==null||work.nativeGuard==null||work.background==null||taskWeb!=null||frame!=current||!owns(task))
            throw new StaleObservation("原生动作缺少同次独立工作与会话");
        actionCheck(work);NativeAppSession.ActionGuard guard=work.nativeGuard;BackgroundSession background=work.background;
        guard.requireOpen(action,work.state.modelRunId,SystemClock.elapsedRealtime());
        NativeAppEvidence.Frame original=guard.frame;
        if(guard.authorization!=work.authorization||background.selection!=guard.selection
                ||work.expected!=frame||!task.equals(work.state.taskId)||guard.deadline!=work.state.deadlineElapsed
                ||guard.issued>work.state.queuedElapsed
                ||background.selection.taskTarget!=guard.target||guard.target.nativeGoal!=guard.goal
                ||!task.equals(original.taskId)||!task.equals(background.taskId)||!original.observationId.equals(frame.id)
                ||!original.stateSha.equals(frame.treeSha256)||!original.treeSha.equals(frame.state.appTreeSha256)
                ||!original.screenshotSha.equals(frame.screenshotSha256)||original.capturedElapsedMs!=frame.capturedElapsedMillis
                ||original.windowId!=frame.windowId||original.rotation!=frame.rotation||original.width!=frame.width||original.height!=frame.height
                ||!original.generation.equals(background.generation)||original.displayId!=background.displayId()
                ||!original.ownerSha.equals(background.ownerSha256)||!original.packageName.equals(frame.packageName)
                ||!original.selectionSha.equals(NativeAppObservation.selectionSha(background.selection))
                ||!frame.backgroundAllowedPackages.equals(java.util.Collections.singletonList(original.packageName))
                ||!original.packageName.equals(frame.backgroundBootstrapPackage)||!"click".equals(action.action)
                ||!original.observationId.equals(action.observationId)||!guard.targetNode.id.equals(action.nodeId))
            throw new StaleObservation("原生动作原观察、目标或任务身份变化");
        background.requireActive();actionCheck(work);
    }
    /** A fresh census remains a census, never a replacement PhoneObservation. */
    private static NativeActionSnapshotCheck.Snapshot nativeActionSnapshot(Graph graph,NativeAppSession.ActionGuard guard){
        PhoneObservation.CollectionStats stats=graph.collectionStats;NativeAppEvidence.Frame frame=guard.frame;
        if(graph.nativeActionNodes==null||graph.nativeActionWindows==null||graph.truncated||stats==null||stats.truncated()
                ||graph.state==null||graph.state.imeVisibility!=ImeVisibility.HIDDEN||graph.windowMetadata==null
                ||!frame.taskId.equals(graph.nativeActionTaskId)||!frame.authorizationSha.equals(graph.nativeActionAuthorizationSha)
                ||!frame.selectionSha.equals(graph.nativeActionSelectionSha)||!frame.targetSha.equals(graph.nativeActionTargetSha)
                ||!guard.goal.contractSha256.equals(graph.nativeActionGoalSha)||!frame.ownerSha.equals(graph.backgroundOwnerSha)
                ||!frame.generation.equals(graph.backgroundGeneration)||!frame.packageName.equals(graph.packageName)
                ||frame.displayId!=graph.displayId||frame.width!=graph.nativeActionWidth||frame.height!=graph.nativeActionHeight
                ||stats.childSlotsOmitted>Integer.MAX_VALUE)
            throw new StaleObservation("原生完整访问快照缺失、越界或不属于原Attempt");
        Map<String,Object> env=new java.util.TreeMap<String,Object>(guard.identity);
        env.put("package",graph.packageName);env.put("display_id",graph.displayId);env.put("window_id",graph.windowId);
        env.put("rotation",graph.rotation);env.put("width",graph.nativeActionWidth);env.put("height",graph.nativeActionHeight);
        env.put("root_bounds",java.util.Arrays.asList(graph.bounds.left,graph.bounds.top,graph.bounds.right,graph.bounds.bottom));
        env.put("window_metadata_sha256",sha(graph.windowMetadata.bindFreshness("").getBytes(StandardCharsets.UTF_8)));
        env.put("reported_windows_sha256",NativeAppEvidence.fingerprint(graph.nativeActionWindows));env.put("reported_windows_complete",true);
        env.put("ime_visibility","hidden");env.put("captured_elapsed_ms",Long.valueOf(graph.nativeActionCapturedAt));
        env.put("full_native_complete",true);env.put("visited",stats.visited);env.put("pending",stats.pending);
        env.put("node_omissions",stats.nodeBudgetOmissions);env.put("text_omissions",stats.textBudgetOmissions);
        env.put("child_omissions",Integer.valueOf((int)stats.childSlotsOmitted));
        return new NativeActionSnapshotCheck.Snapshot(env,graph.nativeActionNodes);
    }
    private Map<String,Object> compareNativeAction(String task,PhoneObservation frame,ActionDecision action,Graph fresh,ActionWork work)throws Exception{
        requireNativeActionGuard(task,frame,action,work);NativeAppSession.ActionGuard guard=work.nativeGuard;
        Graph original=work.graph;
        if(!original.sameWindow(fresh))throw new StaleObservation("原生动作窗口变化");
        NodeRef before=original.refs.get(action.nodeId),after=null;
        for(PhoneObservation.Node row:fresh.rows)if(guard.targetNode.path.equals(row.nativeTreePath)){
            if(after!=null)throw new StaleObservation("原生同路径目标不唯一");after=fresh.refs.get(row.id);
        }
        if(before==null||after==null||!before.node.equals(after.node)||!before.signature.equals(after.signature)
                ||!before.appTreeSignature.equals(guard.targetNode.signature))
            throw new StaleObservation("原始NodeRef与同路径新节点不是同一目标");
        NativeActionSnapshotCheck.Snapshot oldSnapshot=nativeActionSnapshot(original,guard);
        NativeActionSnapshotCheck.Snapshot newSnapshot=nativeActionSnapshot(fresh,guard);
        Map<String,Object> proof=NativeActionSnapshotCheck.compare(guard.intent(before.signature),oldSnapshot,newSnapshot,SystemClock.elapsedRealtime());
        actionCheck(work);return proof;
    }
    /** The final whole-census comparison includes every protected form field,
     * not just the clicked control. Later live checks cover the original target
     * and its actual parent/child chain; they do not claim an atomic UI. */
    private void finalNativeActionCheck(String task,PhoneObservation frame,ActionDecision action,ActionWork work)throws Exception{
        requireNativeActionGuard(task,frame,action,work);NativeAppSession.ActionGuard guard=work.nativeGuard;
        guard.verifyInstalled();actionCheck(work);
        Graph fresh=null;
        try{
            actionPhase(work,"graph_read");fresh=readGraph(work.budget(),work.background);
            Map<String,Object> proof=compareNativeAction(task,frame,action,fresh,work);
            Map<String,Object> windowsBefore=readNativeActionWindows(fresh,work.budget());
            if(!fresh.nativeActionWindows.equals(windowsBefore))throw new StaleObservation("完整复核后原生窗口集合变化");
            NativeActionSnapshotCheck.Snapshot original=nativeActionSnapshot(work.graph,guard);
            refreshNativeActionTargetChain(work.background,frame,work.graph.refs.get(action.nodeId),guard.targetNode.path,original,work);
            Map<String,Object> windowsAfter=readNativeActionWindows(fresh,work.budget());
            if(!windowsBefore.equals(windowsAfter))throw new StaleObservation("原生派发前窗口集合变化");
            requireNativeActionGuard(task,frame,action,work);authorizationBeforeDispatch(task,work.authorization,action,work.state.modelRunId);
            Map<String,Object> evidence=new java.util.TreeMap<String,Object>(proof);
            evidence.put("final_complete_census_compared",true);evidence.put("original_node_ref_and_actual_ancestor_chain",true);
            evidence.put("reported_windows_before_after_equal",true);evidence.put("all_nodes_simultaneous_or_pixels_stable_claimed",false);
            evidence.put("installed_identity_rechecked_before_final_census",true);evidence.put("checked_elapsed_ms",SystemClock.elapsedRealtime());
            String raw=new JSONObject(evidence).toString();
            if(raw.getBytes(StandardCharsets.UTF_8).length>262144)throw new StaleObservation("原生复核证明超出固定记录预算");
            work.nativeActionProof=raw;actionCheck(work);
            guard.claim(action,work.state.modelRunId,SystemClock.elapsedRealtime());guard.requireClaimed();actionCheck(work);
        }finally{if(fresh!=null)fresh.close();}
    }
    private void refreshNativeActionTargetChain(BackgroundSession background,PhoneObservation frame,NodeRef original,
            String targetPath,NativeActionSnapshotCheck.Snapshot snapshot,ActionWork work)throws Exception{
        if(original==null)throw new StaleObservation("原生动作原节点引用缺失");
        List<AccessibilityNodeInfo> temporary=new ArrayList<AccessibilityNodeInfo>();
        AccessibilityNodeInfo cursor=original.node;String path=targetPath;
        Rect targetBounds=new Rect();cursor.getBoundsInScreen(targetBounds);
        try{
            for(int depth=0;depth<64;depth++){
                NativeActionSnapshotCheck.Node expected=snapshot.node(path);actionCheck(work);
                if(!refreshActionNode(work,cursor)||!cursor.isVisibleToUser()||!cursor.isEnabled()||cursor.isPassword())
                    throw new StaleObservation("原生动作目标祖先不可用");
                requireBackgroundNodeWindow(background,frame,cursor);actionCheck(work);
                Rect bounds=new Rect();cursor.getBoundsInScreen(bounds);
                if(!bounds.contains(targetBounds))throw new StaleObservation("原生动作祖先不再包含原目标");
                NativeActionSnapshotCheck.Node actual=snapshotNativeActionNode(cursor,path,expected.parent,null,null);
                Map<String,Object> before=new java.util.TreeMap<String,Object>(expected.v),now=new java.util.TreeMap<String,Object>(actual.v);
                // A retained ancestor's derived label is covered by its full original signature.
                before.remove("label");before.remove("ref_signature_sha256");now.remove("label");now.remove("ref_signature_sha256");
                if(!before.equals(now))throw new StaleObservation("原生目标祖先属性或选择状态变化");
                Object fullSignatureSha256=expected.v.get("ref_signature_sha256");
                if(fullSignatureSha256!=null&&!fullSignatureSha256.equals(NativeAppEvidence.hash(
                        nodeSignature(cursor,observedChildText(cursor,true,work.budget())))))
                    throw new StaleObservation("原生目标祖先签名变化");
                AccessibilityNodeInfo parent=regionParent(work,cursor,temporary);
                if("0".equals(path)){
                    if(parent!=null||!frame.windowMetadata.bindFreshness("").equals(
                            readWindowMetadata(cursor,bounds,frame.windowId,background.displayId()).bindFreshness("")))
                        throw new StaleObservation("原生根或窗口元数据变化");
                    actionCheck(work);return;
                }
                int slash=path.lastIndexOf('/'),index=Integer.parseInt(path.substring(slash+1));
                if(parent==null||!refreshActionNode(work,parent)||index>=parent.getChildCount()
                        ||!expected.parent.equals(string(parent.getClassName())))
                    throw new StaleObservation("原生动作父节点关系变化");
                AccessibilityNodeInfo child=regionChild(work,parent,index,temporary);
                if(child==null||!refreshActionNode(work,child)||!child.equals(cursor))
                    throw new StaleObservation("原生动作实际父子身份变化");
                cursor=parent;path=path.substring(0,slash);
            }
            throw new StaleObservation("原生动作祖先预算不足");
        }finally{for(AccessibilityNodeInfo node:temporary)node.recycle();}
    }

    private String validate(String taskId,PhoneObservation expected,ActionDecision action,ObservedTargetLabels targets,Cancellation cancel,ActionWork work){
        Graph graph=graphForAction(work);
        if(cancel.isCancelled()||!owns(taskId))return "任务已停止";
        if(locked())return "手机已锁定";
        try{requireBackgroundObservation(taskId,expected);}catch(Exception mismatch){return "后台观察无效："+message(mismatch);}
        if(expected!=current||graph==null||!expected.id.equals(action.observationId))return "stale:观察标识已失效";
        String bindingError=targetBindingError(expected,action,targets);if(bindingError!=null)return bindingError;
        long age=SystemClock.elapsedRealtime()-expected.capturedElapsedMillis;
        if(age<0||age>MAX_OBSERVATION_AGE_MS)return "stale:观察已过期";
        if(!"open".equals(action.action)&&!org.trillionnium.hepta.background.FixedIntentTools.isTool(action.action)&&!expected.packageName.equals(action.packageName))return "stale:动作应用与观察不一致";
        Graph now=null;
        try{
            actionPhase(work,"graph_read");
            now=readGraph(work==null?null:work.budget(),work==null?currentBackground():work.background);
            if(!graph.sameWindow(now))return "stale:目标窗口已变化";
            if(ActionPolicy.requiresStableTree(action)){
                WebFlightSession web=taskWeb;
                WebFlightNativeStability.Permit permit=web==null?null:web.flightNativePermitForDispatch(action,expected);
                if(permit!=null){
                    try{
                        actionCheck(work);
                        web.acceptFlightNativeCheck(action,expected,
                                requireLiveFlightNativeStability(taskId,expected,action,permit,now,cancel,work));
                        actionCheck(work);
                    }catch(Exception mismatch){throw new StaleObservation("stale:首页目标局部复核失败："+message(mismatch));}
                }else if(!graph.digest.equals(now.digest)){
                    if(work!=null&&work.nativeGuard!=null){
                        try{compareNativeAction(taskId,expected,action,now,work);work.nativeActionRevalidated=true;}
                        catch(Exception mismatch){recordStaleDiagnostic(work,graph,now,action.nodeId);
                            return "stale:原生目的复核失败："+message(mismatch);}
                    }else{recordStaleDiagnostic(work,graph,now,action.nodeId);return "stale:目标窗口内容已变化";}
                }
            }
        }
        catch(StaleObservation changed){return message(changed);}
        catch(Exception e){return backgroundFor(taskId)==null?"stale:无法复核当前窗口":"后台窗口复核失败："+message(e);}
        finally{if(now!=null)now.close();}
        return null;
    }
    private void performOnAction(final String taskId,final PhoneObservation expected,final ActionDecision action,
                               final ObservedTargetLabels targets,final org.trillionnium.hepta.background.FixedIntentTarget fixedTarget,final Cancellation cancel,final ActionCallback callback,
                               final QualificationScopeConfig.Bound dispatchScope,final TaskAuthorization.Gate authorization,final String modelRunId,final ActionWork work){
        final Graph graph=graphForAction(work);
        try{
            authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
            if(backgroundFor(taskId)!=null){
                String bindingError=targetBindingError(expected,action,targets);
                if(bindingError!=null)throw new IllegalArgumentException(bindingError);
            }
            scopeBeforeDispatch(taskId,dispatchScope,expected,action,null,false,work);
            if((scopeFor(taskId).config!=null||backgroundFor(taskId)!=null)&&("click".equals(action.action)||"type".equals(action.action)||"submit".equals(action.action)||"scroll".equals(action.action))){
                NodeRef ref=graph==null?null:graph.refs.get(action.nodeId);
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,ref==null?null:ref.node,true,work);
            }
        }
        catch(Exception error){callback.onResult(new ActionOutcome(false,false,error instanceof StaleObservation,message(error)));return;}
        String invalid=validate(taskId,expected,action,targets,cancel,work);
        if(invalid!=null){callback.onResult(new ActionOutcome(false,false,invalid.startsWith("stale:"),invalid));return;}
        try{
            if("wait".equals(action.action)){
                afterActionDelay(work,new Runnable(){public void run(){callback.onResult(new ActionOutcome(!cancel.isCancelled(),false,false,cancel.isCancelled()?"等待已停止":"等待结束"));}},action.durationMs);return;
            }
            if("done".equals(action.action)){callback.onResult(new ActionOutcome(true,false,false,"模型请求结束；仍需最终观察"));return;}
            if(ActionPolicy.isReadOnlyDiscovery(action)){
                final AppCatalogueRanker snapshot;synchronized(this){snapshot=appDiscovery;}
                if(snapshot==null)throw new IllegalStateException("本次任务的本机应用目录不可用");
                AppCatalogueRanker.Page page=snapshot.search(action.query,action.offset);
                if(cancel.isCancelled()||!owns(taskId)){callback.onResult(new ActionOutcome(false,false,false,"任务已停止"));return;}
                authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                authorization.found(action,modelRunId,page);
                // Pure lookup: no Intent, accessibility action, gesture, shell,
                // network or app launch is dispatched by this tool.
                callback.onResult(new ActionOutcome(true,false,false,"已只读查询本机应用目录",page));return;
            }
            if(org.trillionnium.hepta.background.FixedIntentTools.isTool(action.action)){
                dispatchFixedIntent(taskId,expected,action,targets,fixedTarget,authorization,modelRunId,cancel,callback,dispatchScope,work);return;
            }
            if("open".equals(action.action)){
                if(backgroundFor(taskId)!=null){dispatchBackgroundNavigation(taskId,expected,action,authorization,modelRunId,cancel,callback,work);return;}
                refreshApps();if(!launchable.containsKey(action.packageName))throw new IllegalArgumentException("目标不是已列出的可启动应用");
                Intent launch=getPackageManager().getLaunchIntentForPackage(action.packageName);
                if(launch==null)throw new IllegalArgumentException("找不到应用启动入口");
                launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TOP);
                if(cancel.isCancelled()){callback.onResult(new ActionOutcome(false,false,false,"任务已停止"));return;}
                scopeOpenIntent(taskId,dispatchScope,action.packageName,launch);
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,null,false,work);
                authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                enterActionEffect(work);startActivity(launch);actionEffectReturned(work,Boolean.TRUE);
                try{authorization.opened(action,modelRunId);}catch(Exception retiredAfterOpen){
                    callback.onResult(new ActionOutcome(false,true,false,"应用打开已派发，但授权回执未完成："+message(retiredAfterOpen)));return;
                }
                finishAfter(700,true,"已请求打开应用，下一步将重新观察",callback,work);return;
            }
            if("back".equals(action.action)||"home".equals(action.action)){
                if(backgroundFor(taskId)!=null){dispatchBackgroundNavigation(taskId,expected,action,authorization,modelRunId,cancel,callback,work);return;}
                if(cancel.isCancelled()){callback.onResult(new ActionOutcome(false,false,false,"任务已停止"));return;}
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,null,false,work);
                authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                enterActionEffect(work);
                boolean accepted=performGlobalAction("back".equals(action.action)?GLOBAL_ACTION_BACK:GLOBAL_ACTION_HOME);
                actionEffectReturned(work,Boolean.valueOf(accepted));
                finishAfter(350,accepted,accepted?"系统导航已接受":"系统导航未接受",callback,work);return;
            }
            if("click".equals(action.action)&&action.nodeId==null){coordinateClick(taskId,expected,action,targets,authorization,modelRunId,cancel,callback);return;}
            NodeRef reference=graph.refs.get(action.nodeId);
            if(reference==null)throw new IllegalArgumentException("节点不属于这次观察");
            AccessibilityNodeInfo node=reference.node;
            boolean refreshed=refreshActionNode(work,node);
            if(scopeFor(taskId).config!=null){
                if(!refreshed){scopeFor(taskId).refuse("scope node refresh failed");throw new QualificationScope.Violation("scope node refresh failed");}
            }
            BackgroundSession background=backgroundFor(taskId);
            if(refreshed&&background!=null)requireBackgroundNodeWindow(background,expected,node);
            ObservedChildText.Result freshChildText=refreshed?observedChildText(node,background!=null,work==null?null:work.budget()):ObservedChildText.notApplicable();
            if(!refreshed||!reference.signature.equals(nodeSignature(node,freshChildText))||!node.isVisibleToUser()||!node.isEnabled()){
                callback.onResult(new ActionOutcome(false,false,true,"stale:目标节点已变化"));return;
            }
            if(node.isPassword())throw new IllegalArgumentException("不自动输入或操作密码节点");
            if(!expected.packageName.equals(string(node.getPackageName()))||node.getWindowId()!=expected.windowId)
                throw new IllegalArgumentException("目标节点窗口不一致");
            if(cancel.isCancelled()){callback.onResult(new ActionOutcome(false,false,false,"任务已停止"));return;}
            boolean accepted;
            if("click".equals(action.action)){
                if(!hasAction(node,AccessibilityNodeInfo.ACTION_CLICK))throw new IllegalArgumentException("这个节点没有点击动作");
                // Only actual editability grants the input-focus exemption. A nonzero
                // raw inputType alone can also occur on a noneditable custom TextView.
                PersistentActionPolicy.Decision policy=PersistentActionPolicy.evaluate(string(node.getText()),
                        string(node.getContentDescription()),freshChildText.text,node.isEditable());
                if(!policy.allowed){
                    callback.onResult(new ActionOutcome(false,false,false,policy.reasonCode+": "+policy.detail));return;
                }
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,node,true,work);
                authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                WebFlightSession web=taskWeb;
                if(web!=null){
                    WebRegionNativeBridge region=web.nativeRegionForDispatch(action,modelRunId,expected);
                    if(work!=null&&region!=work.nativeRegion)throw new StaleObservation("商品原生授权已在动作交接后变化");
                    if(region!=null){
                        web.acceptNativeRegionCheck(action,modelRunId,
                                requireLiveNativeRegion(taskId,expected,node,region,cancel,work));
                        scopeBeforeDispatch(taskId,dispatchScope,expected,action,node,true,work);
                        authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                    }
                    web.beforeNativeClickInvocation(action,modelRunId);
                }
                if(work!=null&&work.nativeActionRevalidated){
                    finalNativeActionCheck(taskId,expected,action,work);work.nativeGuard.requireClaimed();
                }
                enterActionEffect(work);accepted=node.performAction(AccessibilityNodeInfo.ACTION_CLICK);actionEffectReturned(work,Boolean.valueOf(accepted));
                finishAfter(350,accepted,accepted?"节点点击已接受":"节点点击未接受",callback,work);
            }else if("type".equals(action.action)){
                if(!node.isEditable()||!hasAction(node,AccessibilityNodeInfo.ACTION_SET_TEXT))throw new IllegalArgumentException("目标不是可写文本节点");
                Bundle args=new Bundle();args.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,action.text);
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,node,true,work);
                authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                enterActionEffect(work);accepted=node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT,args);actionEffectReturned(work,Boolean.valueOf(accepted));
                if(!accepted){callback.onResult(new ActionOutcome(false,false,false,"文本写入未被接受"));return;}
                afterActionDelay(work,new Runnable(){public void run(){
                    if(cancel.isCancelled()||!ownsScope(taskId,dispatchScope)||!ownsAuthorization(taskId,authorization)){
                        callback.onResult(new ActionOutcome(false,true,false,"文本已派发，任务已停止；不读取退休节点"));return;
                    }
                    try{
                        actionPhase(work,"readback");actionCheck(work);
                        boolean verified=reference.node.refresh()&&action.text.equals(string(reference.node.getText()));actionCheck(work);
                        callback.onResult(new ActionOutcome(verified,true,false,verified?"文本已按原文回读验证":"文本操作已发送，但原文回读未通过；不重试"));
                    }catch(RuntimeException retiredNode){
                        callback.onResult(new ActionOutcome(false,true,false,"文本已派发，但节点回读不可用；不重试"));
                    }
                }},300);
            }else if("submit".equals(action.action)){
                if(!(ActionDecision.IME_ACTION_SCHEMA.equals(action.actionSchema)||ActionDecision.FIXED_INTENT_ACTION_SCHEMA.equals(action.actionSchema))||!reference.imeEnter.queryAllowed()
                        ||!node.isEditable()||!node.isFocused()||!ObservedImeEnter.isSha(reference.inputTextSha256))
                    throw new IllegalArgumentException("当前字段没有已观察且语义明确的查询提交动作");
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,node,true,work);
                authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                final SubmitAttemptGuard guard=submitFor(taskId);
                requireSubmitWindow(node,expected.windowId,graph.displayId);
                actionPhase(work,"attempt_journal");
                final SubmitAttemptGuard.Attempt attempt=guard.consume(new SubmitAttemptGuard.Binding(taskId,modelRunId,
                        expected.id,expected.packageName,action.nodeId,expected.windowId,graph.displayId,
                        expected.backgroundGeneration,reference.inputTextSha256,reference.imeEnter));
                try{
                    // The durable journal can take time. Revalidate before consuming the platform call.
                    String changed=validate(taskId,expected,action,targets,cancel,work);
                    if(changed!=null)throw new IllegalStateException(changed);
                    scopeBeforeDispatch(taskId,dispatchScope,expected,action,node,true,work);
                    authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                    if(cancel.isCancelled()||!refreshActionNode(work,node)||!node.isEditable()||!node.isFocused()||!node.isVisibleToUser()
                            ||!node.isEnabled()||node.isPassword()||node.getWindowId()!=expected.windowId
                            ||!expected.packageName.equals(string(node.getPackageName()))
                            ||!reference.signature.equals(nodeSignature(node,observedChildText(node,background!=null,work==null?null:work.budget()))))
                        throw new IllegalStateException("提交记录已消费，但字段或任务已变化；未调用编辑器，不重试");
                    requireSubmitWindow(node,expected.windowId,graph.displayId);
                    guard.entering(attempt);enterActionEffect(work);
                    boolean apiAccepted=node.performAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.getId());
                    actionEffectReturned(work,Boolean.valueOf(apiAccepted));
                    final JSONObject proof=new JSONObject(guard.finished(attempt,Boolean.valueOf(apiAccepted)));
                    final ActionOutcome result=new ActionOutcome(apiAccepted,true,false,apiAccepted
                            ?"查询编辑器动作已接受；业务结果仍需重新观察，不重试相同输入":"查询编辑器动作未接受；已记录尝试，不重试").withSubmit(proof);
                    afterActionDelay(work,new Runnable(){public void run(){callback.onResult(result);}},350);
                }catch(Exception uncertain){
                    Map<String,Object> proof=guard.evidence(attempt);
                    boolean entered=Boolean.TRUE.equals(proof.get("dispatch_attempted"));
                    callback.onResult(new ActionOutcome(false,entered,false,"查询提交未完成："+message(uncertain)+"；保留消费记录，不重试")
                            .withSubmit(new JSONObject(proof)));
                }
            }else if("scroll".equals(action.action)){
                int operation=scrollAction(action.direction);
                if(!hasAction(node,operation))throw new IllegalArgumentException("这个节点未提供所选滚动方向");
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,node,true,work);
                authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                enterActionEffect(work);accepted=node.performAction(operation);actionEffectReturned(work,Boolean.valueOf(accepted));finishAfter(450,accepted,accepted?"滚动已接受":"滚动未接受",callback,work);
            }else throw new IllegalArgumentException("不支持的动作");
        }catch(Exception e){callback.onResult(new ActionOutcome(false,work!=null&&work.state.effectEntered(),e instanceof StaleObservation,message(e)));}
    }
    /** IPC runs off the service/main thread. A missing reply is a possible dispatch, never a retry. */
    private void dispatchFixedIntent(final String taskId,final PhoneObservation expected,final ActionDecision action,
            final ObservedTargetLabels labels,final org.trillionnium.hepta.background.FixedIntentTarget target,
            final TaskAuthorization.Gate authorization,final String run,final Cancellation cancel,final ActionCallback callback,
            final QualificationScopeConfig.Bound scope,final ActionWork work)throws Exception{
        if(!ActionDecision.FIXED_INTENT_ACTION_SCHEMA.equals(action.actionSchema)||target==null||!target.action.equals(action.action)
                ||!target.packageName.equals(action.packageName)||!ObservedAppLabels.project(target.appLabel).equals(action.appLabel))
            throw new IllegalStateException("fixed intent target not bound to native decision frame");
        QualificationScope.require(scope.config==null,"fixed intent tools are outside legacy qualification scope");
        final int caller=android.os.Process.myUid();
        final String payload="notes.create".equals(action.action)?action.text:action.query;
        org.trillionnium.hepta.background.FixedIntentDispatch.recheck(this,caller,target);
        final BackgroundSession background=backgroundFor(taskId);
        final int display=background==null?Display.DEFAULT_DISPLAY:background.displayId();
        final FixedIntentAttemptGuard ledger=fixedIntentsFor(taskId);
        // Consume and fsync before either ordinary Android or broker call. A failed journal cannot dispatch.
        actionPhase(work,"attempt_journal");
        final FixedIntentAttemptGuard.Attempt attempt=ledger.consume(new FixedIntentAttemptGuard.Binding(taskId,run,expected.id,
                expected.packageName,expected.windowId,display,background==null?null:background.generation,target,payload));
        try{
            if(cancel.isCancelled())throw new IllegalStateException("task cancelled before fixed intent");
            String invalid=validate(taskId,expected,action,labels,cancel,work);if(invalid!=null)throw new IllegalStateException(invalid);
            scopeBeforeDispatch(taskId,scope,expected,action,null,false,work);authorizationBeforeDispatch(taskId,authorization,action,run);
            org.trillionnium.hepta.background.FixedIntentDispatch.recheck(this,caller,target);
            if(background==null){
                Intent intent=org.trillionnium.hepta.background.FixedIntentDispatch.intent(target,payload);
                ledger.entering(attempt);enterActionEffect(work);
                try{startActivity(intent);actionEffectReturned(work,Boolean.TRUE);ledger.finished(attempt,Boolean.TRUE);}
                catch(Exception unknown){ledger.finished(attempt,null);callback.onResult(new ActionOutcome(false,true,false,"固定本地入口派发结果未知，不自动重试："+message(unknown)).withFixedIntent(new JSONObject(ledger.evidence(attempt))));return;}
                afterActionDelay(work,new Runnable(){public void run(){callback.onResult(new ActionOutcome(true,true,false,
                        "固定本地入口请求已接受；须重新观察编辑器/搜索页，尚未证明保存或查询结果").withFixedIntent(new JSONObject(ledger.evidence(attempt))));}},700);
                return;
            }
            executeActionIo(work,new Runnable(){public void run(){
                boolean entered=false;
                try{
                    if(cancel.isCancelled()||!ownsBackground(taskId,background))throw new IllegalStateException("background task retired");
                    scope.verifyUnchanged();authorizationBeforeDispatch(taskId,authorization,action,run);background.requireActive();
                    org.trillionnium.hepta.background.FixedIntentDispatch.recheck(HeptaAccessibilityService.this,caller,target);
                    ledger.entering(attempt);entered=true;enterActionEffect(work);
                    JSONObject response=background.fixedIntent(target,payload,attempt.id,actionCancellation(work,cancel),work==null?Long.MAX_VALUE:work.state.deadlineElapsed);
                    actionEffectReturned(work,Boolean.TRUE);
                    ledger.finished(attempt,Boolean.TRUE);
                    final JSONObject proof=new JSONObject(ledger.evidence(attempt)).put("broker_response",response);
                    afterActionDelay(work,new Runnable(){public void run(){callback.onResult(new ActionOutcome(true,true,false,
                            "后台固定本地入口已派发；须重新观察，尚未证明保存或查询结果").withFixedIntent(proof));}},350);
                }catch(final Exception failure){
                    if(entered)ledger.finished(attempt,null);
                    final JSONObject proof=new JSONObject(ledger.evidence(attempt));final boolean dispatched=entered;
                    deliverActionCallback(work,new Runnable(){public void run(){callback.onResult(new ActionOutcome(false,dispatched,false,
                            "后台固定本地入口未得到完整确认，不自动重试："+message(failure)).withFixedIntent(proof));}});
                }
            }});
        }catch(Exception beforeCall){
            Map<String,Object> proof=ledger.evidence(attempt);
            boolean entered=Boolean.TRUE.equals(proof.get("dispatch_attempted"))||(work!=null&&work.state.effectEntered());
            callback.onResult(new ActionOutcome(false,entered,false,(entered?"固定本地入口派发状态未知，不重试：":"固定本地入口未派发，尝试已消费：")
                    +message(beforeCall)).withFixedIntent(new JSONObject(proof)));
        }
    }

    private void dispatchBackgroundNavigation(final String id,final PhoneObservation expected,final ActionDecision action,
            final TaskAuthorization.Gate authorization,final String modelRunId,final Cancellation cancel,final ActionCallback callback,final ActionWork work){
        final BackgroundSession background=backgroundFor(id);
        if(background==null||"home".equals(action.action)){callback.onResult(new ActionOutcome(false,false,false,"后台 HOME 不可用"));return;}
        try{executeActionIo(work,new Runnable(){public void run(){
            boolean sent=false;
            try{
                if(cancel.isCancelled()||!ownsBackground(id,background))throw new IllegalStateException("后台任务已停止");
                scopeFor(id).verifyUnchanged();authorizationBeforeDispatch(id,authorization,action,modelRunId);
                background.requireActive();enterActionEffect(work);sent=true;
                JSONObject receipt=background.action("open".equals(action.action)?"launch":"back",action.packageName,actionCancellation(work,cancel),work==null?Long.MAX_VALUE:work.state.deadlineElapsed);
                actionEffectReturned(work,Boolean.TRUE);
                final boolean dispatched=receipt.optBoolean("dispatched",true);
                if("open".equals(action.action)&&dispatched)authorization.opened(action,modelRunId);
                final ActionOutcome result=new ActionOutcome(true,dispatched,false,"后台工具已定向派发；下一步重新观察");
                afterActionDelay(work,new Runnable(){public void run(){callback.onResult(result);}},350);
            }catch(Exception error){
                boolean attempted=sent||(work!=null&&work.state.effectEntered());
                final ActionOutcome result=new ActionOutcome(false,attempted,false,"后台工具未完成："+message(error)+(attempted?"；可能已有派发，不重试":""));
                deliverActionCallback(work,new Runnable(){public void run(){callback.onResult(result);}});
            }
        }});}catch(RuntimeException unavailable){callback.onResult(new ActionOutcome(false,false,false,"后台执行队列已关闭"));}
    }
    private void finishAfter(long delay,final boolean accepted,final String detail,final ActionCallback callback){
        finishAfter(delay,accepted,detail,callback,null);
    }
    private void finishAfter(long delay,final boolean accepted,final String detail,final ActionCallback callback,ActionWork work){
        afterActionDelay(work,new Runnable(){public void run(){callback.onResult(new ActionOutcome(accepted,accepted,false,detail));}},delay);
    }
    private void coordinateClick(final String taskId,final PhoneObservation expected,final ActionDecision action,
                                 final ObservedTargetLabels targets,final TaskAuthorization.Gate authorization,final String modelRunId,
                                 final Cancellation cancel,final ActionCallback callback){
        if(backgroundFor(taskId)!=null){callback.onResult(new ActionOutcome(false,false,false,"后台任务禁止坐标手势和主屏回退"));return;}
        if(capturePending){callback.onResult(new ActionOutcome(false,false,true,"stale:截图正在更新"));return;}
        final int x=Math.min(expected.width-1,(int)Math.round(action.x*(expected.width-1)/1000.0));
        final int y=Math.min(expected.height-1,(int)Math.round(action.y*(expected.height-1)/1000.0));
        if(!expected.windowBounds.contains(x,y)){callback.onResult(new ActionOutcome(false,false,false,"坐标不在已观察应用窗口内"));return;}
        capturePending=true;lastScreenshotAt=SystemClock.elapsedRealtime();final long token=++captureSerial;
        main.postDelayed(new Runnable(){public void run(){
            if(capturePending&&captureSerial==token){capturePending=false;captureSerial++;callback.onResult(new ActionOutcome(false,false,true,"stale:点击前截图回调超时"));}
        }},5000);
        try { takeScreenshot(Display.DEFAULT_DISPLAY,getMainExecutor(),new TakeScreenshotCallback(){
            @Override public void onFailure(int code){
                if(captureSerial!=token)return;capturePending=false;captureSerial++;
                callback.onResult(new ActionOutcome(false,false,true,"stale:点击前截图校验失败，代码 "+code));}
            @Override public void onSuccess(ScreenshotResult result){
                if(captureSerial!=token){result.getHardwareBuffer().close();return;}
                capturePending=false;captureSerial++;Bitmap fresh=null;
                try{
                    fresh=copyScreenshot(result);String invalid=validate(taskId,expected,action,targets,cancel,null);
                    if(invalid!=null){callback.onResult(new ActionOutcome(false,false,invalid.startsWith("stale:"),invalid));return;}
                    if(fresh.getWidth()!=expected.width||fresh.getHeight()!=expected.height||!samePatch(currentBitmap,fresh,x,y)){
                        callback.onResult(new ActionOutcome(false,false,true,"stale:点击目标像素已变化"));return;
                    }
                    if(cancel.isCancelled()){callback.onResult(new ActionOutcome(false,false,false,"任务已停止"));return;}
                    authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                    Path path=new Path();path.moveTo(x,y);
                    GestureDescription gesture=new GestureDescription.Builder().addStroke(new GestureDescription.StrokeDescription(path,0,80)).build();
                    boolean queued=dispatchGesture(gesture,new GestureResultCallback(){
                        @Override public void onCompleted(GestureDescription value){finishAfter(300,true,"坐标点击完成，下一步将重新观察",callback);}
                        @Override public void onCancelled(GestureDescription value){callback.onResult(new ActionOutcome(false,true,false,"手势中断，可能已有部分效果；不重试"));}
                    },main);
                    if(!queued)callback.onResult(new ActionOutcome(false,false,false,"系统未接受坐标手势"));
                }catch(Exception e){callback.onResult(new ActionOutcome(false,false,false,message(e)));}
                finally{if(fresh!=null)fresh.recycle();}
            }
        }); } catch(Exception error){
            if(captureSerial==token){capturePending=false;captureSerial++;callback.onResult(new ActionOutcome(false,false,false,"点击前截图不可用："+message(error)));}
        }
    }
    private static boolean samePatch(Bitmap a,Bitmap b,int x,int y){
        if(a==null)return false;int left=Math.max(0,x-24),top=Math.max(0,y-24),right=Math.min(a.getWidth(),x+25),bottom=Math.min(a.getHeight(),y+25);
        int width=right-left,height=bottom-top;int[] first=new int[width*height],second=new int[width*height];
        a.getPixels(first,0,width,left,top,width,height);b.getPixels(second,0,width,left,top,width,height);
        return java.util.Arrays.equals(first,second);
    }
    private static boolean hasAction(AccessibilityNodeInfo node,int id){for(AccessibilityNodeInfo.AccessibilityAction a:node.getActionList())if(a.getId()==id)return true;return false;}
    private static int scrollAction(String direction){
        if("forward".equals(direction))return AccessibilityNodeInfo.ACTION_SCROLL_FORWARD;
        if("backward".equals(direction))return AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD;
        if("up".equals(direction))return AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_UP.getId();
        if("down".equals(direction))return AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_DOWN.getId();
        if("left".equals(direction))return AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_LEFT.getId();
        if("right".equals(direction))return AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_RIGHT.getId();
        throw new IllegalArgumentException("未知滚动方向");
    }
    private static final class NodeRef {
        final AccessibilityNodeInfo node;final String signature,appTreeSignature;
        final ObservedImeEnter imeEnter;final String inputTextSha256;
        private NodeRef(NodeRef original){
            node=AccessibilityNodeInfo.obtain(original.node);signature=original.signature;appTreeSignature=original.appTreeSignature;
            imeEnter=original.imeEnter;inputTextSha256=original.inputTextSha256;
        }
        NodeRef(AccessibilityNodeInfo node,ObservedChildText.Result childText,ObservedScrollActions scrollActions){
            this(node,childText,scrollActions,readImeEnter(node),inputTextHash(node));
        }
        NodeRef(AccessibilityNodeInfo node,ObservedChildText.Result childText,ObservedScrollActions scrollActions,ObservedImeEnter imeEnter,String inputTextSha256){
            this.node=AccessibilityNodeInfo.obtain(node);this.imeEnter=imeEnter;this.inputTextSha256=inputTextSha256;
            this.appTreeSignature=childText.bind(baseNodeSignature(node));
            this.signature=imeEnter.bindFreshness(scrollActions.bindFreshness(appTreeSignature),node.isFocused(),inputTextSha256);
        }
    }
    private static final class Graph {
        PhoneObservation.CollectionStats collectionStats;
        ObservationDiagnostics.GraphStamp diagnosticStamp;
        // Set only by fresh readGraph; partial action copies deliberately keep false.
        boolean nativeObservationComplete;
        String packageName,digest,backgroundGeneration,backgroundBootstrapPackage;int windowId,rotation,displayId;Rect bounds;boolean truncated;
        List<String> backgroundAllowedPackages=java.util.Collections.emptyList();
        String backgroundSelectionRaw,backgroundOwnerSha;
        ObservationState state;
        ObservedWindowMetadata windowMetadata;
        final List<PhoneObservation.Node> rows=new ArrayList<PhoneObservation.Node>();
        final Map<String,NodeRef> refs=new HashMap<String,NodeRef>();
        // Mutable builders belong only to readGraph's worker. The action handoff
        // carries immutable serialized evidence, never shared rows or a mutable JSONArray.
        JSONArray flightNativeSnapshot;boolean flightNativeSnapshotComplete;int flightNativeSnapshotText;
        int flightNativeSnapshotLimit=WebFlightNativeStability.MAX_NATIVE_NODES;
        String flightNativeSnapshotRaw,flightRetainedSnapshotRaw;
        // Separate complete BFS census. Action handoff shares immutable values only.
        List<NativeActionSnapshotCheck.Node> nativeActionBuilding,nativeActionNodes;
        Map<String,Object> nativeActionWindows;int nativeActionText,nativeActionBytes,nativeActionWidth,nativeActionHeight;
        long nativeActionCapturedAt;
        String nativeActionTaskId,nativeActionAuthorizationSha,nativeActionSelectionSha,nativeActionTargetSha,nativeActionGoalSha;
        void freezeFlightSnapshots(GraphBudget budget){
            if(flightNativeSnapshot==null)return;
            try{
                checkReadBudget(budget);
                if(!flightNativeSnapshotComplete||collectionStats==null
                        ||flightNativeSnapshot.length()!=collectionStats.visited
                        ||rows.size()>flightNativeSnapshotLimit)
                    throw new IllegalStateException("complete bounded Flight snapshot unavailable");
                JSONArray retained=new JSONArray();
                for(PhoneObservation.Node row:rows){checkReadBudget(budget);retained.put(row.json());}
                flightNativeSnapshotRaw=org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(flightNativeSnapshot);
                flightRetainedSnapshotRaw=org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(retained);
                checkReadBudget(budget);
            }catch(Exception unavailable){
                flightNativeSnapshotComplete=false;flightNativeSnapshotRaw=null;flightRetainedSnapshotRaw=null;
            }finally{flightNativeSnapshot=null;}
        }
        boolean sameWindow(Graph other){return windowId==other.windowId&&rotation==other.rotation&&displayId==other.displayId
                &&java.util.Objects.equals(backgroundGeneration,other.backgroundGeneration)
                &&java.util.Objects.equals(backgroundSelectionRaw,other.backgroundSelectionRaw)
                &&java.util.Objects.equals(backgroundOwnerSha,other.backgroundOwnerSha)
                &&packageName.equals(other.packageName)&&bounds.equals(other.bounds);}
        boolean sameWindowAndTree(Graph other){return sameWindow(other)&&digest.equals(other.digest);}
        Graph copyForAction(String nodeId,WebRegionNativeBridge region){
            // Main-looper handoff clones local references only: one selected node, or exactly four product roles plus their WebView.
            // No refresh, traversal, live-window query, or other IPC occurs during this bounded handoff.
            Graph copy=new Graph();copy.packageName=packageName;copy.digest=digest;copy.backgroundGeneration=backgroundGeneration;
            copy.backgroundBootstrapPackage=backgroundBootstrapPackage;copy.windowId=windowId;copy.rotation=rotation;
            copy.displayId=displayId;copy.bounds=new Rect(bounds);copy.truncated=truncated;
            copy.backgroundAllowedPackages=java.util.Collections.unmodifiableList(new ArrayList<String>(backgroundAllowedPackages));
            copy.backgroundSelectionRaw=backgroundSelectionRaw;copy.backgroundOwnerSha=backgroundOwnerSha;
            copy.state=state;copy.windowMetadata=windowMetadata;copy.collectionStats=collectionStats;
            copy.diagnosticStamp=diagnosticStamp; // Immutable hashes/geometry only; no new node copy or live read.
            // O(1) evidence transfer; complete snapshots were frozen on the read worker.
            copy.flightNativeSnapshotComplete=flightNativeSnapshotComplete;copy.flightNativeSnapshotLimit=flightNativeSnapshotLimit;
            copy.flightNativeSnapshotRaw=flightNativeSnapshotRaw;copy.flightRetainedSnapshotRaw=flightRetainedSnapshotRaw;
            copy.nativeActionNodes=nativeActionNodes;copy.nativeActionWindows=nativeActionWindows;
            copy.nativeActionWidth=nativeActionWidth;copy.nativeActionHeight=nativeActionHeight;copy.nativeActionCapturedAt=nativeActionCapturedAt;
            copy.nativeActionTaskId=nativeActionTaskId;copy.nativeActionAuthorizationSha=nativeActionAuthorizationSha;
            copy.nativeActionSelectionSha=nativeActionSelectionSha;copy.nativeActionTargetSha=nativeActionTargetSha;copy.nativeActionGoalSha=nativeActionGoalSha;
            try{
                NodeRef selected=nodeId==null?null:refs.get(nodeId);if(selected!=null)copy.refs.put(nodeId,new NodeRef(selected));
                if(region!=null){
                    if(selected==null||!region.anchor.id.equals(nodeId)||region.roles().size()!=4)
                        throw new StaleObservation("商品动作缺少原始四角色快照");
                    for(WebRegionNativeBridge.Role role:region.roles()){
                        NodeRef original=refs.get(role.nodeId);
                        if(original==null)throw new StaleObservation("商品动作缺少原始角色引用");
                        if(!copy.refs.containsKey(role.nodeId))copy.refs.put(role.nodeId,new NodeRef(original));
                    }
                    NodeRef web=refs.get(region.nativeWebViewId);
                    if(web==null||copy.refs.containsKey(region.nativeWebViewId))throw new StaleObservation("商品动作缺少独立 WebView 引用");
                    copy.refs.put(region.nativeWebViewId,new NodeRef(web));
                    if(copy.refs.size()!=5)throw new StaleObservation("商品原生角色快照并非四个独立角色");
                }
                return copy;
            }catch(RuntimeException failure){copy.close();throw failure;}
        }
        void close(){for(NodeRef n:refs.values())n.node.recycle();refs.clear();}
    }
    private interface GraphBudget { void check(); }
    private static void checkReadBudget(GraphBudget budget){if(budget!=null)budget.check();}
    /** Inspect window metadata only. Never traverse an IME root or collect its text. */
    private ImeVisibility readImeVisibility(int targetWindowId,int targetDisplayId){
        List<AccessibilityWindowInfo> windows=null;
        try{
            AccessibilityServiceInfo info=getServiceInfo();
            if(info==null||(info.flags&AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS)==0
                    ||(info.getCapabilities()&AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT)==0)
                return ImeVisibility.UNKNOWN;
            windows=windowsForDisplay(targetDisplayId);
            if(windows==null||windows.isEmpty())return ImeVisibility.UNKNOWN;
            boolean complete=true,targetPresent=false,imePresent=false;
            for(AccessibilityWindowInfo window:windows){
                if(window==null){complete=false;continue;}
                if(window.getDisplayId()!=targetDisplayId)continue;
                if(window.getId()==targetWindowId)targetPresent=true;
                if(window.getType()==AccessibilityWindowInfo.TYPE_INPUT_METHOD){
                    Rect bounds=new Rect();window.getBoundsInScreen(bounds);
                    if(bounds.isEmpty())complete=false;else imePresent=true;
                }
            }
            return ImeVisibility.observed(complete,targetPresent,imePresent);
        }catch(RuntimeException unavailable){return ImeVisibility.UNKNOWN;}
        finally{if(windows!=null)for(AccessibilityWindowInfo window:windows)if(window!=null){
            try{window.recycle();}catch(RuntimeException ignored){/* No visibility conclusion from cleanup. */}
        }}
    }
    /** Read only the selected root's window metadata; never traverse another/IME window. */
    private ObservedWindowMetadata readWindowMetadata(AccessibilityNodeInfo root,Rect rootBounds,int windowId,int targetDisplayId){
        int[] bounds=new int[]{rootBounds.left,rootBounds.top,rootBounds.right,rootBounds.bottom};
        String rootClass=null;
        AccessibilityWindowInfo window=null;
        try{
            CharSequence actualClass=root.getClassName();rootClass=actualClass==null?null:actualClass.toString();
            window=root.getWindow();
            if(window==null||window.getId()!=windowId||window.getDisplayId()!=targetDisplayId)
                return ObservedWindowMetadata.unknown(bounds,rootClass);
            Rect actualBounds=new Rect();window.getBoundsInScreen(actualBounds);
            int type=window.getType();
            // An input-method window is never a source of title/input text here.
            CharSequence actualTitle=type==AccessibilityWindowInfo.TYPE_INPUT_METHOD?null:window.getTitle();
            return ObservedWindowMetadata.observed(bounds,rootClass,type,window.getDisplayId(),
                    new int[]{actualBounds.left,actualBounds.top,actualBounds.right,actualBounds.bottom},
                    actualTitle==null?null:actualTitle.toString());
        }catch(RuntimeException unavailable){return ObservedWindowMetadata.unknown(bounds,rootClass);}
        finally{if(window!=null)try{window.recycle();}catch(RuntimeException ignored){/* Cleanup supplies no metadata. */}}
    }
    private static final class NoActiveWindow extends IllegalStateException {
        private static final long serialVersionUID=1L;
        NoActiveWindow(){super("没有活动窗口");}
    }
    private List<AccessibilityWindowInfo> windowsForDisplay(int displayId){
        SparseArray<List<AccessibilityWindowInfo>> all=getWindowsOnAllDisplays();
        if(all==null)return java.util.Collections.emptyList();
        List<AccessibilityWindowInfo> selected=all.get(displayId);
        for(int i=0;i<all.size();i++)if(all.keyAt(i)!=displayId){
            List<AccessibilityWindowInfo> others=all.valueAt(i);if(others!=null)for(AccessibilityWindowInfo window:others)if(window!=null)window.recycle();
        }
        return selected==null?java.util.Collections.<AccessibilityWindowInfo>emptyList():selected;
    }
    /** A background root comes only from the immutable display ID; own-focus need not be globally active. */
    private AccessibilityNodeInfo selectedRoot(){return selectedRoot(currentBackground(),null);}
    private AccessibilityNodeInfo selectedRoot(BackgroundSession background,GraphBudget budget){
        checkReadBudget(budget);
        if(background==null)return getRootInActiveWindow();
        background.requireActive();List<AccessibilityWindowInfo> windows=windowsForDisplay(background.displayId());
        AccessibilityWindowInfo chosen=null;
        try{
            checkReadBudget(budget);
            for(AccessibilityWindowInfo window:windows){
                checkReadBudget(budget);
                if(window==null||window.getDisplayId()!=background.displayId()||window.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION)continue;
                if(chosen==null||(window.isFocused()&&!chosen.isFocused())
                        ||(window.isFocused()==chosen.isFocused()&&window.getLayer()>chosen.getLayer()))chosen=window;
            }
            if(chosen==null)throw new NoActiveWindow();
            AccessibilityNodeInfo root=chosen.getRoot();if(root==null)throw new NoActiveWindow();
            try{
                checkReadBudget(budget);boolean refreshed=root.refresh();checkReadBudget(budget);background.requireActive();
                if(!refreshed)throw new StaleObservation("后台根节点已不可用，需重新观察");
                if(root.getWindowId()!=chosen.getId()||!background.allows(string(root.getPackageName()))||!root.isVisibleToUser())
                    throw new IllegalStateException("后台屏幕出现未授权应用或不可见窗口，任务停止");
                return root;
            }catch(RuntimeException error){root.recycle();throw error;}
        }finally{for(AccessibilityWindowInfo window:windows)if(window!=null)window.recycle();}
    }
    /** Complete bounded raw AccessibilityNodeInfo facts from this very BFS.
     * This is not a PhoneObservation or dispatch authority. Unretained ancestors
     * and children are read, never manufactured from the retained rows. */
    private static NativeActionSnapshotCheck.Node snapshotNativeActionNode(AccessibilityNodeInfo node,String path,
            String parentClass,PhoneObservation.Node retained,NodeRef reference){
        Rect bounds=new Rect();node.getBoundsInScreen(bounds);
        String text=node.isPassword()?"":string(node.getText());
        String description=node.isPassword()?"":string(node.getContentDescription());
        String label=null,fullSignatureSha256=null;
        if(retained!=null){
            if(reference==null||!path.equals(retained.nativeTreePath)||!reference.node.equals(node)
                    ||!reference.appTreeSignature.equals(retained.observedAppTreeSignature)
                    ||retained.selected==null||retained.checkable==null||retained.checked==null
                    ||retained.selected.booleanValue()!=node.isSelected()||retained.checkable.booleanValue()!=node.isCheckable()
                    ||retained.checked.booleanValue()!=node.isChecked()||!retained.bounds.equals(bounds))
                throw new StaleObservation("原生完整快照与同次保留节点不一致");
            label=retained.label();if(retained.text.trim().isEmpty()&&retained.description.trim().isEmpty()
                    &&!"derived".equals(retained.childText.status))label="";
            label=ObservedTargetLabels.project(label);fullSignatureSha256=NativeAppEvidence.hash(reference.signature);
        }else if(reference!=null)throw new StaleObservation("无保留节点的引用不可作为快照事实");
        Map<String,Object> row=new java.util.TreeMap<String,Object>();
        row.put("path",path);row.put("parent_class",parentClass);row.put("package",string(node.getPackageName()));
        row.put("window_id",node.getWindowId());row.put("class",string(node.getClassName()));
        row.put("view_id",string(node.getViewIdResourceName()));row.put("text",text);row.put("description",description);
        row.put("label",label);row.put("ref_signature_sha256",fullSignatureSha256);
        row.put("bounds",java.util.Arrays.asList(bounds.left,bounds.top,bounds.right,bounds.bottom));
        row.put("visible",node.isVisibleToUser()&&!bounds.isEmpty());row.put("enabled",node.isEnabled());
        row.put("clickable",node.isClickable());row.put("editable",node.isEditable());row.put("scrollable",node.isScrollable());
        row.put("focused",node.isFocused());row.put("password",node.isPassword());
        row.put("selected",node.isSelected());row.put("checkable",node.isCheckable());row.put("checked",node.isChecked());
        row.put("children",node.getChildCount());row.put("scroll_actions",readScrollActions(node).fingerprintInput());
        row.put("ime_enter",readImeEnter(node).fingerprintInput());row.put("input_sha256",inputTextHash(node));
        row.put("action_click",hasAction(node,AccessibilityNodeInfo.ACTION_CLICK));
        return new NativeActionSnapshotCheck.Node(row);
    }
    /** Only metadata of all reported windows on the selected display. No other
     * window root/title/text is read; absent/unreported windows are not proved. */
    private Map<String,Object> readNativeActionWindows(Graph graph,GraphBudget budget){
        checkReadBudget(budget);AccessibilityServiceInfo info=getServiceInfo();checkReadBudget(budget);
        if(info==null||(info.flags&AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS)==0
                ||(info.getCapabilities()&AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT)==0
                ||graph.windowMetadata==null||!"observed".equals(graph.windowMetadata.status)
                ||graph.windowMetadata.type==null||graph.windowMetadata.type.intValue()!=1)
            throw new StaleObservation("原生动作窗口集合或元数据不可用");
        List<AccessibilityWindowInfo> windows=windowsForDisplay(graph.displayId);
        if(windows==null)throw new StaleObservation("原生动作窗口集合缺失");
        try{
            if(windows.isEmpty()||windows.size()>64)throw new StaleObservation("原生动作窗口集合超出完整预算");
            java.util.TreeMap<Integer,Map<String,Object>> rows=new java.util.TreeMap<Integer,Map<String,Object>>();
            int targetLayer=-1;Rect targetBounds=null;
            for(AccessibilityWindowInfo window:windows){
                checkReadBudget(budget);
                if(window==null||window.getDisplayId()!=graph.displayId||window.getId()<0||window.getType()<=0||window.getLayer()<0)
                    throw new StaleObservation("原生动作窗口身份未知");
                Rect bounds=new Rect();window.getBoundsInScreen(bounds);
                if(bounds.isEmpty())throw new StaleObservation("原生动作窗口范围未知");
                Map<String,Object> row=new java.util.TreeMap<String,Object>();row.put("window_id",window.getId());
                row.put("display_id",window.getDisplayId());row.put("type",window.getType());row.put("layer",window.getLayer());
                row.put("bounds",java.util.Arrays.asList(bounds.left,bounds.top,bounds.right,bounds.bottom));
                row.put("focused",window.isFocused());row.put("active",window.isActive());
                if(rows.put(window.getId(),row)!=null)throw new StaleObservation("原生动作窗口身份重复");
                if(window.getId()==graph.windowId){
                    if(window.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION)throw new StaleObservation("原生目标窗口类型变化");
                    targetLayer=window.getLayer();targetBounds=new Rect(bounds);
                }
                if(window.getType()==AccessibilityWindowInfo.TYPE_INPUT_METHOD)throw new StaleObservation("原生导航复核要求已知隐藏输入法");
            }
            int[] expected=graph.windowMetadata.windowBounds();
            if(targetLayer<0||targetBounds==null||expected==null||expected.length!=4
                    ||targetBounds.left!=expected[0]||targetBounds.top!=expected[1]||targetBounds.right!=expected[2]
                    ||targetBounds.bottom!=expected[3]||!targetBounds.contains(graph.bounds))
                throw new StaleObservation("原生目标窗口或根范围变化");
            for(AccessibilityWindowInfo window:windows)if(window.getId()!=graph.windowId&&window.getLayer()>=targetLayer){
                checkReadBudget(budget);Rect bounds=new Rect();window.getBoundsInScreen(bounds);
                if(Rect.intersects(bounds,graph.bounds))throw new StaleObservation("原生目标根被报告窗口覆盖");
            }
            Map<String,Object> result=new java.util.TreeMap<String,Object>();result.put("display_id",graph.displayId);
            result.put("target_window_id",graph.windowId);result.put("target_layer",targetLayer);
            result.put("windows",new ArrayList<Map<String,Object>>(rows.values()));
            result.put("other_window_roots_traversed",false);result.put("unreported_windows_excluded",false);
            checkReadBudget(budget);return NativeAppEvidence.immutableMap(result);
        }finally{for(AccessibilityWindowInfo window:windows)if(window!=null)window.recycle();}
    }
    @SuppressWarnings("deprecation")
    private void beginNativeActionCensus(Graph graph,BackgroundSession background,GraphBudget budget){
        try{
            checkReadBudget(budget);TaskAuthorization.Gate auth=taskAuthorization;
            if(background==null||auth==null||!background.taskId.equals(auth.taskId)||!ownsAuthorization(background.taskId,auth)
                    ||background.selection.taskTarget==null||background.selection.taskTarget.nativeGoal==null)
                throw new StaleObservation("原生完整快照没有当前任务授权");
            DisplayManager manager=(DisplayManager)getSystemService(DISPLAY_SERVICE);
            Display display=manager==null?null:manager.getDisplay(graph.displayId);
            if(display==null||display.getRotation()!=graph.rotation)throw new StaleObservation("原生显示尺寸或旋转未知");
            android.util.DisplayMetrics metrics=new android.util.DisplayMetrics();display.getRealMetrics(metrics);
            if(metrics.widthPixels<=0||metrics.heightPixels<=0)throw new StaleObservation("原生显示范围未知");
            graph.nativeActionWidth=metrics.widthPixels;graph.nativeActionHeight=metrics.heightPixels;
            graph.nativeActionTaskId=background.taskId;graph.nativeActionAuthorizationSha=auth.authorization.sha256;
            graph.nativeActionSelectionSha=NativeAppObservation.selectionSha(background.selection);
            graph.nativeActionTargetSha=background.selection.taskTarget.targetSha256;
            graph.nativeActionGoalSha=background.selection.taskTarget.nativeGoal.contractSha256;
            graph.nativeActionWindows=readNativeActionWindows(graph,budget);
            graph.nativeActionBuilding=new ArrayList<NativeActionSnapshotCheck.Node>();
        }catch(Exception unavailable){graph.nativeActionBuilding=null;graph.nativeActionWindows=null;}
        checkReadBudget(budget);
    }
    private static void collectNativeActionNode(Graph graph,AccessibilityNodeInfo node,String path,String parent,
            PhoneObservation.Node retained,NodeRef reference){
        if(graph.nativeActionBuilding==null)return;
        try{
            if(graph.nativeActionBuilding.size()>=NativeActionSnapshotCheck.MAX_NODES)throw new IllegalStateException("native census node cap");
            NativeActionSnapshotCheck.Node row=snapshotNativeActionNode(node,path,parent,retained,reference);
            graph.nativeActionText+=row.text.length()+row.desc.length();
            graph.nativeActionBytes+=new JSONObject(row.v).toString().getBytes(StandardCharsets.UTF_8).length;
            if(graph.nativeActionText>NativeActionSnapshotCheck.MAX_TEXT||graph.nativeActionBytes>NativeActionSnapshotCheck.MAX_BYTES)
                throw new IllegalStateException("native census text/byte cap");
            graph.nativeActionBuilding.add(row);
        }catch(RuntimeException unavailable){graph.nativeActionBuilding=null;graph.nativeActionNodes=null;}
    }
    @SuppressWarnings("deprecation")
    private void finishNativeActionCensus(Graph graph,GraphBudget budget){
        if(graph.nativeActionBuilding==null)return;
        try{
            checkReadBudget(budget);
            if(!graph.nativeObservationComplete||graph.state.imeVisibility!=ImeVisibility.HIDDEN
                    ||graph.collectionStats.visited!=graph.nativeActionBuilding.size()
                    ||!graph.nativeActionWindows.equals(readNativeActionWindows(graph,budget)))
                throw new StaleObservation("原生完整快照、输入法或窗口集合变化");
            DisplayManager manager=(DisplayManager)getSystemService(DISPLAY_SERVICE);Display display=manager==null?null:manager.getDisplay(graph.displayId);
            android.util.DisplayMetrics metrics=new android.util.DisplayMetrics();
            if(display==null)throw new StaleObservation("原生显示已退休");display.getRealMetrics(metrics);
            if(display.getRotation()!=graph.rotation||metrics.widthPixels!=graph.nativeActionWidth||metrics.heightPixels!=graph.nativeActionHeight)
                throw new StaleObservation("原生显示尺寸或旋转变化");
            graph.nativeActionNodes=java.util.Collections.unmodifiableList(new ArrayList<NativeActionSnapshotCheck.Node>(graph.nativeActionBuilding));
            graph.nativeActionCapturedAt=SystemClock.elapsedRealtime();checkReadBudget(budget);
        }catch(RuntimeException unavailable){graph.nativeActionNodes=null;}
        finally{graph.nativeActionBuilding=null;}
        checkReadBudget(budget);
    }

    private Graph readGraph(){return readGraph(null,currentBackground());}
    private Graph readGraph(GraphBudget budget,BackgroundSession background){
        checkReadBudget(budget);
        String actualSelectionRaw=null,actualOwnerSha=null;
        if(background!=null)try{
            background.requireActive();actualSelectionRaw=background.selection.json().toString();actualOwnerSha=background.ownerSha256;
        }catch(Exception missingSelection){throw new IllegalStateException("无法记录当前后台应用选择来源",missingSelection);}
        checkReadBudget(budget);
        AccessibilityNodeInfo root=selectedRoot(background,budget);if(root==null)throw new NoActiveWindow();
        Graph graph=new Graph();
        ArrayDeque<AccessibilityNodeInfo> queue=new ArrayDeque<AccessibilityNodeInfo>();queue.add(root);
        try{
        checkReadBudget(budget);
        WebFlightSession activeWeb=taskWeb;
        boolean webEvidence=activeWeb!=null&&background!=null&&activeWeb.taskId.equals(background.taskId)
                &&background.selection.allowedPackages.equals(java.util.Collections.singletonList(
                        org.trillionnium.hepta.webprotocol.WebEvidenceProtocol.HELPER_PACKAGE));
        BackgroundTaskTarget nativeTarget=background==null?null:background.selection.taskTarget;
        NativeAppGoal nativeGoal=nativeTarget==null?null:nativeTarget.nativeGoal;
        boolean nativeEvidence=activeWeb==null&&nativeTarget!=null&&nativeGoal!=null
                &&nativeTarget.explicitSelection&&BackgroundTaskTarget.NATIVE_APP.equals(nativeTarget.route)
                &&nativeGoal.ownerSha256.equals(background.ownerSha256)
                &&nativeTarget.ownerSha256.equals(background.ownerSha256)
                &&nativeGoal.packageName.equals(nativeTarget.packageName)
                &&nativeTarget.packageName.equals(background.selection.initialPackage)
                &&nativeTarget.packageName.equals(string(root.getPackageName()))
                &&background.selection.allowedPackages.equals(java.util.Collections.singletonList(nativeTarget.packageName));
        int retainedLimit=webEvidence?WEB_MAX_NODES:nativeEvidence?NATIVE_APP_MAX_NODES:MAX_NODES;
        int textLimit=webEvidence?WEB_MAX_CHARACTERS:MAX_CHARACTERS;
        graph.displayId=background==null?Display.DEFAULT_DISPLAY:background.displayId();
        if(webEvidence&&(activeWeb.goal!=null||activeWeb.purpose.shopping!=null)){
            graph.flightNativeSnapshotLimit=activeWeb.goal!=null?WebFlightNativeStability.MAX_NATIVE_NODES:WebShoppingObservationStability.MAX_NATIVE_NODES;
            graph.flightNativeSnapshot=new JSONArray();graph.flightNativeSnapshotComplete=true;
        }
        graph.backgroundGeneration=background==null?null:background.generation;
        graph.backgroundBootstrapPackage=background==null?null:background.selection.initialPackage;
        graph.backgroundAllowedPackages=background==null?java.util.Collections.<String>emptyList():background.selection.allowedPackages;
        graph.backgroundSelectionRaw=actualSelectionRaw;graph.backgroundOwnerSha=actualOwnerSha;
        graph.packageName=string(root.getPackageName());graph.windowId=root.getWindowId();graph.rotation=rotation(graph.displayId);graph.bounds=new Rect();root.getBoundsInScreen(graph.bounds);
        if(graph.packageName.isEmpty()||graph.bounds.isEmpty())throw new IllegalStateException("活动窗口身份不可用");
        graph.windowMetadata=readWindowMetadata(root,graph.bounds,graph.windowId,graph.displayId);
        // Native selection facts are read-only. Their presence grants no action
        // or provider support; the same explicitly selected singleton App owns them.
        boolean nativeSelectionFacts=background!=null
                &&background.selection.allowedPackages.equals(java.util.Collections.singletonList(graph.packageName))
                &&(NativeAppGoal.CTRIP_PACKAGE.equals(graph.packageName)
                    ||NativeAppGoal.CSAIR_PACKAGE.equals(graph.packageName)
                    ||NativeAppGoal.XIAOMI_PACKAGE.equals(graph.packageName));
        if(background!=null&&(graph.windowMetadata.displayId==null||graph.windowMetadata.displayId.intValue()!=graph.displayId
                ||!background.allows(graph.packageName)))throw new IllegalStateException("后台观察窗口越界");
        if(nativeEvidence)beginNativeActionCensus(graph,background,budget);
        ArrayDeque<String> nativePaths=new ArrayDeque<String>(),nativeParents=new ArrayDeque<String>();
        nativePaths.add("0");nativeParents.add("");
        StringBuilder signatures=new StringBuilder(),focusStates=new StringBuilder(),scrollStates=new StringBuilder();int visited=0,characters=0;
        int nodeBudgetOmissions=0,textBudgetOmissions=0;long childSlotsOmitted=0,started=SystemClock.elapsedRealtime();
            while(!queue.isEmpty()&&visited<MAX_VISITED){
                checkReadBudget(budget);
                AccessibilityNodeInfo node=queue.removeFirst();visited++;
                String nativePath=nativePaths.removeFirst(),nativeParentClass=nativeParents.removeFirst();
                try{
                    // selectedRoot refreshed the root before graph metadata was read.
                    // Descendants may still be cached; never publish an old body as a new frame.
                    if(background!=null&&node!=root&&!node.refresh())throw new StaleObservation("后台子节点已不可用，需重新观察");
                    checkReadBudget(budget);Rect bounds=new Rect();node.getBoundsInScreen(bounds);boolean visible=node.isVisibleToUser()&&!bounds.isEmpty();
                    // Preserve at most94 owner units plus the exact40-LF provider
                    // form for the already selected background Notes app. The
                    // global text budget, raw hash and completion rule stay unchanged.
                    boolean notesEditorText=background!=null&&node.isEditable()
                            &&background.selection.allowedPackages.equals(java.util.Collections.singletonList(NotesCompletionEvidence.NOTES))
                            &&NotesCompletionEvidence.NOTES.equals(string(node.getPackageName()));
                    String text=node.isPassword()?"":limited(string(node.getText()),notesEditorText?134:96);
                    String description=node.isPassword()?"":limited(string(node.getContentDescription()),96);
                    ObservedScrollActions scrollActions=readScrollActions(node);
                    ObservedImeEnter imeEnter=readImeEnter(node);String inputHash=inputTextHash(node);
                    PhoneObservation.Node nativeRetained=null;NodeRef nativeReference=null;
                    boolean useful=visible&&(node.isClickable()||node.isEditable()||node.isScrollable()||!text.isEmpty()||!description.isEmpty());
                    if(useful){
                        ObservedChildText.Result childText=graph.rows.size()<retainedLimit?observedChildText(node,background!=null,budget):ObservedChildText.notApplicable();
                        if(graph.rows.size()<retainedLimit&&characters+text.length()+description.length()+childText.text.length()<textLimit){
                            String id="n"+graph.rows.size();NodeRef reference=new NodeRef(node,childText,scrollActions,imeEnter,inputHash);graph.refs.put(id,reference);signatures.append(reference.appTreeSignature).append('|')
                                    .append(nativePath).append('|').append(nativeParentClass).append('\n');
                            Boolean selected=nativeSelectionFacts?Boolean.valueOf(node.isSelected()):null;
                            Boolean checkable=nativeSelectionFacts?Boolean.valueOf(node.isCheckable()):null;
                            Boolean checked=nativeSelectionFacts?Boolean.valueOf(node.isChecked()):null;
                            if(nativeSelectionFacts)signatures.append("native_selection|").append(nativePath).append('|')
                                    .append(selected).append('|').append(checkable).append('|').append(checked).append('\n');
                            scrollStates.append(id).append('=').append(scrollActions.fingerprintInput()).append('\n');
                            boolean focused=node.isFocused();focusStates.append(id).append('=').append(focused).append('|').append(imeEnter.fingerprintInput()).append('|').append(inputHash).append('\n');
                            graph.rows.add(new PhoneObservation.Node(id,string(node.getPackageName()),string(node.getClassName()),limited(string(node.getViewIdResourceName()),96),text,description,bounds,node.isClickable(),node.isEditable(),node.isScrollable(),node.isEnabled(),focused,node.isPassword(),childText,scrollActions,imeEnter,inputHash,
                                    node.isEditable()&&focused&&node.isEnabled()&&!node.isPassword()&&imeEnter.queryAllowed()&&submitAvailable(string(node.getPackageName()),inputHash),reference.appTreeSignature,
                                    nativePath.isEmpty()?null:nativePath,nativePath.isEmpty()?null:nativeParentClass,
                                    selected,checkable,checked));
                            nativeRetained=graph.rows.get(graph.rows.size()-1);nativeReference=reference;
                            characters+=text.length()+description.length()+childText.text.length();
                        }else{
                            graph.truncated=true;
                            if(graph.rows.size()>=retainedLimit)nodeBudgetOmissions++;else textBudgetOmissions++;
                        }
                    }
                    if(nativeEvidence)collectNativeActionNode(graph,node,nativePath,nativeParentClass,nativeRetained,nativeReference);
                    int actualChildren=node.getChildCount();
                    if(graph.flightNativeSnapshot!=null&&graph.flightNativeSnapshotComplete){
                        try{
                            if(graph.flightNativeSnapshot.length()>=graph.flightNativeSnapshotLimit)
                                throw new IllegalStateException("bounded full Flight snapshot exceeded");
                            JSONObject stamp=snapshotFlightNode(node,nativePath,nativeParentClass);
                            int chars=stamp.getString("text").length()+stamp.getString("description").length();
                            if(graph.flightNativeSnapshotText+chars>32768)
                                throw new IllegalStateException("bounded full Flight snapshot text exceeded");
                            graph.flightNativeSnapshotText+=chars;graph.flightNativeSnapshot.put(stamp);
                        }catch(Exception unavailable){graph.flightNativeSnapshotComplete=false;}
                    }
                    int children=Math.min(actualChildren,MAX_VISITED-visited-queue.size());
                    if(children<actualChildren){graph.truncated=true;childSlotsOmitted+=(long)actualChildren-children;}
                    for(int index=0;index<children;index++){
                        checkReadBudget(budget);AccessibilityNodeInfo child=node.getChild(index);
                        if(child!=null){
                            queue.add(child);
                            // Beyond this small position budget retain the node, but publish no hierarchy claim.
                            nativePaths.add(nativePath.isEmpty()||nativePath.length()>=240?"":nativePath+"/"+index);
                            nativeParents.add(limited(string(node.getClassName()),96));
                        }else if(background!=null)throw new StaleObservation("后台子树已变化，需重新观察");
                    }
                }finally{node.recycle();}
            }
            checkReadBudget(budget);if(!queue.isEmpty())graph.truncated=true;
            graph.collectionStats=new PhoneObservation.CollectionStats(MAX_VISITED,retainedLimit,textLimit,
                    visited,graph.rows.size(),characters,queue.size(),nodeBudgetOmissions,textBudgetOmissions,
                    childSlotsOmitted,SystemClock.elapsedRealtime()-started);
            String binding=background==null?"":("background="+background.generation+"|display="+graph.displayId+"|owner="+graph.backgroundOwnerSha
                    +"|selection="+sha(graph.backgroundSelectionRaw.getBytes(StandardCharsets.UTF_8))+"|");
            String appTree=sha((binding+graph.packageName+"|"+graph.windowId+"|"+graph.rotation+"|"+graph.bounds+"|"+signatures).getBytes(StandardCharsets.UTF_8));
            graph.state=new ObservationState(appTree,readImeVisibility(graph.windowId,graph.displayId));
            // Focus is newly model-visible evidence, not an expansion of the old progress predicate.
            graph.digest=sha(graph.windowMetadata.bindFreshness(graph.state.fingerprintInput()+"\nnode_focus="+focusStates+"\nnode_scroll_actions="+scrollStates)
                    .getBytes(StandardCharsets.UTF_8));checkReadBudget(budget);
            graph.nativeObservationComplete=nativeEvidence&&completeNativeObservationGraph(graph);
            if(nativeEvidence)finishNativeActionCensus(graph,budget);
            if(nativeEvidence)graph.diagnosticStamp=nativeDiagnosticStamp(graph);
            graph.freezeFlightSnapshots(budget);checkReadBudget(budget);return graph;
        }catch(RuntimeException e){graph.close();throw e;}
        finally{while(!queue.isEmpty())queue.removeFirst().recycle();}
    }
    /** Completeness under the existing bounded observable-node policy, not all Android nodes. */
    private static boolean completeNativeObservationGraph(Graph graph){
        PhoneObservation.CollectionStats stats=graph.collectionStats;
        ObservedWindowMetadata window=graph.windowMetadata;
        if(graph.truncated||stats==null||stats.truncated()||stats.visited<1||stats.retained<1
                ||stats.retained!=graph.rows.size()||stats.visited<stats.retained||stats.pending!=0
                ||stats.nodeBudgetOmissions!=0||stats.textBudgetOmissions!=0||stats.childSlotsOmitted!=0
                ||graph.refs.size()!=graph.rows.size()||graph.state==null||graph.state.imeVisibility==ImeVisibility.UNKNOWN
                ||window==null||!"observed".equals(window.status)||window.type==null||window.type.intValue()!=1
                ||window.displayId==null||window.displayId.intValue()!=graph.displayId
                ||window.rootClassTruncated||window.titleTruncated)return false;
        int[] root=window.rootBounds(),bounds=window.windowBounds();
        if(root==null||bounds==null||root[0]!=graph.bounds.left||root[1]!=graph.bounds.top
                ||root[2]!=graph.bounds.right||root[3]!=graph.bounds.bottom
                ||bounds[0]>root[0]||bounds[1]>root[1]||bounds[2]<root[2]||bounds[3]<root[3])return false;
        java.util.HashSet<String> paths=new java.util.HashSet<String>();
        for(PhoneObservation.Node row:graph.rows){
            NodeRef ref=graph.refs.get(row.id);
            if(!graph.packageName.equals(row.packageName)||row.nativeTreePath==null||!paths.add(row.nativeTreePath)
                    ||!row.selectionStateObserved||ref==null||row.observedAppTreeSignature==null
                    ||!row.observedAppTreeSignature.equals(ref.appTreeSignature))return false;
        }
        return true;
    }
    /** Reduce existing selected-App rows; never refresh or traverse an extra node. */
    private static ObservationDiagnostics.GraphStamp nativeDiagnosticStamp(Graph graph){
        try{
            if(graph.backgroundGeneration==null||graph.rows.size()>ObservationDiagnostics.MAX_NODES)return null;
            List<ObservationDiagnostics.NodeStamp> rows=new ArrayList<ObservationDiagnostics.NodeStamp>();
            for(PhoneObservation.Node row:graph.rows){
                if(!graph.packageName.equals(row.packageName))return null;
                String flags=row.clickable+"|"+row.editable+"|"+row.scrollable+"|"+row.enabled+"|"+row.focused+"|"+row.password
                        +"|"+row.selected+"|"+row.checkable+"|"+row.checked+"|"+row.scrollActions.fingerprintInput()
                        +"|"+row.imeEnter.fingerprintInput()+"|"+row.inputTextSha256;
                rows.add(new ObservationDiagnostics.NodeStamp(row.id,row.nativeTreePath,row.observedAppTreeSignature,
                        sha(flags.getBytes(StandardCharsets.UTF_8)),row.bounds.left,row.bounds.top,row.bounds.right,row.bounds.bottom));
            }
            return new ObservationDiagnostics.GraphStamp(graph.packageName,graph.backgroundGeneration,graph.backgroundOwnerSha,
                    graph.displayId,graph.windowId,graph.state.appTreeSha256,graph.digest,
                    sha(graph.windowMetadata.bindFreshness("").getBytes(StandardCharsets.UTF_8)),graph.truncated,rows);
        }catch(RuntimeException unavailable){return null;}
    }
    private static JSONObject snapshotFlightNode(AccessibilityNodeInfo node,String path,String parentClass)throws Exception{
        String text=node.isPassword()?"":string(node.getText()),description=node.isPassword()?"":string(node.getContentDescription());
        if(path==null||path.isEmpty()||path.length()>240||text.length()>1024||description.length()>1024
                ||string(node.getViewIdResourceName()).length()>256||string(node.getClassName()).length()>128)
            throw new IllegalStateException("complete bounded Flight node fields unavailable");
        Rect r=new Rect();node.getBoundsInScreen(r);
        return new JSONObject().put("path",path).put("parent_class",parentClass)
                .put("package",string(node.getPackageName())).put("window_id",node.getWindowId())
                .put("class",string(node.getClassName())).put("view_id",string(node.getViewIdResourceName()))
                .put("text",text).put("description",description)
                .put("bounds",new JSONArray(new int[]{r.left,r.top,r.right,r.bottom}))
                .put("visible",node.isVisibleToUser()&&!r.isEmpty()).put("enabled",node.isEnabled())
                .put("clickable",node.isClickable()).put("editable",node.isEditable()).put("scrollable",node.isScrollable())
                .put("focused",node.isFocused()).put("password",node.isPassword()).put("children",node.getChildCount())
                .put("scroll_actions",readScrollActions(node).fingerprintInput())
                .put("ime_enter",readImeEnter(node).fingerprintInput())
                .put("input_sha256",inputTextHash(node)==null?JSONObject.NULL:inputTextHash(node));
    }
    private FlightNativeCheck requireLiveFlightNativeStability(String taskId,PhoneObservation frame,ActionDecision action,
            WebFlightNativeStability.Permit permit,Graph now,Cancellation cancel,ActionWork work)throws Exception{
        // Background actions reach this only on actionIo with their independently owned target.
        // A legacy main-thread path cannot acquire this scoped Flight exception.
        if(work==null)throw new StaleObservation("首页复核缺少独立动作工作");
        actionCheck(work);long started=SystemClock.elapsedRealtime();
        BackgroundSession background=work.background;Graph before=work.graph;
        if(background==null||before==null||frame!=current||cancel.isCancelled()||!owns(taskId)
                ||!taskId.equals(permit.taskId)||permit.frame!=frame||permit.windowId!=before.windowId
                ||permit.displayId!=before.displayId||!before.sameWindow(now)
                ||before.truncated||now.truncated||before.collectionStats==null||now.collectionStats==null
                ||before.collectionStats.truncated()||now.collectionStats.truncated()
                ||!before.flightNativeSnapshotComplete||!now.flightNativeSnapshotComplete
                ||before.flightNativeSnapshotRaw==null||now.flightNativeSnapshotRaw==null
                ||before.flightRetainedSnapshotRaw==null||now.flightRetainedSnapshotRaw==null
                ||before.state.imeVisibility!=ImeVisibility.HIDDEN||now.state.imeVisibility!=ImeVisibility.HIDDEN
                ||!before.windowMetadata.bindFreshness("").equals(now.windowMetadata.bindFreshness("")))
            throw new StaleObservation("完整原生树、输入法或窗口元数据不可证明");
        JSONArray oldNative=new JSONArray(before.flightNativeSnapshotRaw),newNative=new JSONArray(now.flightNativeSnapshotRaw);
        JSONArray oldRetained=new JSONArray(before.flightRetainedSnapshotRaw),newRetained=new JSONArray(now.flightRetainedSnapshotRaw);
        if(oldNative.length()!=before.collectionStats.visited||newNative.length()!=now.collectionStats.visited
                ||oldRetained.length()!=before.collectionStats.retained||newRetained.length()!=now.collectionStats.retained)
            throw new StaleObservation("完整原生树与保留节点计数不匹配");
        actionCheck(work);background.requireActive();actionCheck(work);
        NodeRef original=before.refs.get(action.nodeId),fresh=null;
        for(PhoneObservation.Node row:now.rows)if(permit.targetPath.equals(row.nativeTreePath)){
            if(fresh!=null)throw new StaleObservation("原生目标路径不唯一");fresh=now.refs.get(row.id);
        }
        if(original==null||fresh==null||!original.node.equals(fresh.node)||!original.signature.equals(fresh.signature))
            throw new StaleObservation("原始节点引用与同路径新目标不相同");
        JSONObject proof=WebFlightNativeStability.compareNative(oldNative,newNative,permit.targetPath);
        proof.put("retained_node_pairing",WebFlightNativeStability.compareRetained(oldRetained,newRetained,
                proof.getString("native_slider_path")));
        actionCheck(work);
        JSONObject windowsBefore=readRegionWindows(frame,permit.displayId,permit.windowId,permit.bounds(),work);
        refreshFlightTargetChain(background,frame,original,permit.targetPath,oldNative,work);
        if(!original.signature.equals(nodeSignature(original.node,observedChildText(original.node,true,work.budget()))))
            throw new StaleObservation("原始目标最后签名已变化");
        actionCheck(work);
        JSONObject windowsAfter=readRegionWindows(frame,permit.displayId,permit.windowId,permit.bounds(),work);
        if(!org.trillionnium.hepta.webprotocol.WebDomCanonical.same(windowsBefore,windowsAfter))
            throw new StaleObservation("首页点击前窗口覆盖关系已变化");
        background.requireActive();actionCheck(work);
        if(cancel.isCancelled()||!owns(taskId)||frame!=current)throw new StaleObservation("首页任务已退休");
        return new FlightNativeCheck(frame,permit,started,SystemClock.elapsedRealtime(),proof,windowsAfter,before.digest.equals(now.digest));
    }
    private void refreshFlightTargetChain(BackgroundSession background,PhoneObservation frame,NodeRef original,
                                         String targetPath,JSONArray snapshot,ActionWork work)throws Exception{
        actionCheck(work);
        java.util.Map<String,JSONObject> records=new java.util.HashMap<String,JSONObject>();
        for(int i=0;i<snapshot.length();i++){JSONObject row=snapshot.getJSONObject(i);records.put(row.getString("path"),row);}
        java.util.List<AccessibilityNodeInfo> owned=new java.util.ArrayList<AccessibilityNodeInfo>();
        AccessibilityNodeInfo cursor=original.node;String path=targetPath;
        Rect target=new Rect();cursor.getBoundsInScreen(target);
        try{
            for(int depth=0;depth<64;depth++){
                actionCheck(work);JSONObject expected=records.get(path);
                if(expected==null||!refreshActionNode(work,cursor)||!cursor.isVisibleToUser()||!cursor.isEnabled()||cursor.isPassword())
                    throw new StaleObservation("首页目标祖先不可用");
                actionCheck(work);requireBackgroundNodeWindow(background,frame,cursor);actionCheck(work);
                Rect actual=new Rect();cursor.getBoundsInScreen(actual);
                if(!actual.contains(target)||!org.trillionnium.hepta.webprotocol.WebDomCanonical.same(expected,
                        snapshotFlightNode(cursor,path,expected.getString("parent_class"))))
                    throw new StaleObservation("首页目标祖先或原生几何已变化");
                AccessibilityNodeInfo parent=regionParent(work,cursor,owned);
                if("0".equals(path)){
                    if(parent!=null)throw new StaleObservation("首页原生根边界变化");return;
                }
                int slash=path.lastIndexOf('/'),index=Integer.parseInt(path.substring(slash+1));
                if(parent==null||!refreshActionNode(work,parent)||index>=parent.getChildCount()
                        ||!expected.getString("parent_class").equals(string(parent.getClassName())))
                    throw new StaleObservation("首页目标父节点关系变化");
                AccessibilityNodeInfo child=regionChild(work,parent,index,owned);
                if(child==null||!refreshActionNode(work,child)||!child.equals(cursor))throw new StaleObservation("首页目标父子身份变化");
                cursor=parent;path=path.substring(0,slash);
            }
            throw new StaleObservation("首页原生祖先预算不足");
        }finally{for(AccessibilityNodeInfo node:owned)node.recycle();}
    }
    /** A main handoff or an owned read worker; abandonment never frees a running native read. */
    private final class FlightObservationRead<T> implements Runnable {
        private final java.util.concurrent.Callable<T> read;private final Cancellation cancel;private final long deadline;
        private final Runnable cleanup;private boolean done,abandoned;private T value;private Throwable error;
        FlightObservationRead(java.util.concurrent.Callable<T> read,Cancellation cancel,long deadline,Runnable cleanup){
            this.read=read;this.cancel=cancel;this.deadline=deadline;this.cleanup=cleanup;
        }
        private void requireOpen(){
            if(cancel.isCancelled()||SystemClock.elapsedRealtime()>=deadline)
                throw new IllegalStateException("readonly Flight observation cancelled or expired");
        }
        @Override public void run(){
            T actual=null;Throwable failure=null;
            try{
                synchronized(this){if(abandoned)return;}
                requireOpen();actual=read.call();requireOpen();
            }catch(Throwable refused){failure=refused;}
            finally{
                // Owned node copies and the process-wide read slot drain before any result is published.
                try{if(cleanup!=null)cleanup.run();}
                catch(Throwable releaseFailure){if(failure==null)failure=releaseFailure;else failure.addSuppressed(releaseFailure);}
                synchronized(this){
                    try{if(abandoned||failure!=null)releaseValue(actual);else value=actual;}
                    catch(Throwable releaseFailure){if(failure==null)failure=releaseFailure;else failure.addSuppressed(releaseFailure);}
                    error=failure;done=true;notifyAll();
                }
            }
        }
        private void releaseValue(Object result){
            if(result instanceof FlightObservationSnapshot)((FlightObservationSnapshot)result).close();
        }
        T await()throws Exception{
            boolean claimed=false;
            try{
                synchronized(this){
                    while(!done){requireOpen();wait(Math.min(50,Math.max(1,deadline-SystemClock.elapsedRealtime())));}
                    requireOpen();
                    if(error instanceof Exception)throw (Exception)error;
                    if(error instanceof Error)throw (Error)error;
                    T result=value;value=null;claimed=true;return result;
                }
            }finally{if(!claimed)synchronized(this){abandoned=true;releaseValue(value);value=null;}}
        }
    }
    private <T>T readFlightObservationOnMain(java.util.concurrent.Callable<T> read,Cancellation cancel,long deadline)throws Exception{
        if(Looper.myLooper()==Looper.getMainLooper())throw new IllegalStateException("Flight observation waits only on its worker");
        FlightObservationRead<T> call=new FlightObservationRead<T>(read,cancel,deadline,null);
        if(!main.post(call))throw new IllegalStateException("readonly Flight observation main looper unavailable");
        return call.await();
    }
    /** In-memory admission only. No scope file, live window, node refresh, or graph traversal on main. */
    private Graph requireFlightObservationCurrent(WebFlightSession web,PhoneObservation frame,Cancellation cancel){
        if(Looper.myLooper()!=Looper.getMainLooper()||web==null||(web.goal==null&&web.purpose.shopping==null)||taskWeb!=web
                ||frame==null||frame!=current||currentGraph==null||cancel.isCancelled()||!owns(web.taskId)
                ||taskScope==null||taskAuthorization!=web.authorization||taskBackground==null)
            throw new StaleObservation("Flight只读观察已退休或不是当前主线程图");
        return currentGraph;
    }
    private static boolean completeFlightGraph(Graph graph){
        return graph!=null&&!graph.truncated&&graph.collectionStats!=null&&!graph.collectionStats.truncated()
                &&graph.collectionStats.pending==0&&graph.collectionStats.childSlotsOmitted==0
                &&graph.flightNativeSnapshotComplete&&graph.flightNativeSnapshotRaw!=null
                &&graph.flightRetainedSnapshotRaw!=null&&graph.state.imeVisibility==ImeVisibility.HIDDEN;
    }
    private synchronized boolean ownsFlightObservation(WebFlightSession web,FlightObservationSnapshot source,PhoneObservation currentFrame){
        return source!=null&&!source.closed&&source.service==this&&source.web==web&&taskWeb==web
                &&currentFrame!=null&&currentFrame==current&&owns(web.taskId)
                &&taskScope==source.scope&&taskAuthorization==source.authorization&&taskAuthorization==web.authorization
                &&taskBackground==source.background&&source.background!=null;
    }
    private void requireFlightObservationLive(WebFlightSession web,FlightObservationSnapshot source,PhoneObservation currentFrame,
            Cancellation cancel,long deadline){
        if(cancel.isCancelled()||SystemClock.elapsedRealtime()>=deadline||!ownsFlightObservation(web,source,currentFrame))
            throw new StaleObservation("Flight只读观察的任务、授权、后台租约或期限已退休");
    }
    private void requireFlightObservationAuthority(WebFlightSession web,FlightObservationSnapshot source,PhoneObservation currentFrame,
            Cancellation cancel,long deadline)throws Exception{
        if(Looper.myLooper()==Looper.getMainLooper())throw new IllegalStateException("Flight authority IO must stay off main");
        requireFlightObservationLive(web,source,currentFrame,cancel,deadline);
        if(locked())throw new StaleObservation("Flight只读观察时手机已锁定");
        source.scope.verifyUnchanged();source.scope.requireReady();source.authorization.ready();
        source.background.requireActive();requireBackgroundObservation(web.taskId,source.frame);
        requireFlightObservationLive(web,source,currentFrame,cancel,deadline);
    }
    private static void requireCompleteFlightSnapshot(FlightObservationSnapshot source)throws Exception{
        if(!completeFlightGraph(source.graph)||source.frameRaw==null
                ||new JSONArray(source.graph.flightNativeSnapshotRaw).length()!=source.graph.collectionStats.visited
                ||new JSONArray(source.graph.flightRetainedSnapshotRaw).length()!=source.graph.collectionStats.retained)
            throw new StaleObservation("Flight只读观察没有完整冻结原生树或保留节点计数不匹配");
    }
    FlightObservationSnapshot retainFlightObservation(final WebFlightSession web,final PhoneObservation frame,
            final Cancellation cancel,final long deadline)throws Exception{
        FlightObservationSnapshot source=readFlightObservationOnMain(new java.util.concurrent.Callable<FlightObservationSnapshot>(){
            public FlightObservationSnapshot call(){
                synchronized(HeptaAccessibilityService.this){
                    Graph graph=requireFlightObservationCurrent(web,frame,cancel);
                    if(!completeFlightGraph(graph))return null;
                    PhoneObservation.Node target=web.purpose.shopping==null?null:WebShoppingObservationStability.target(graph.rows);
                    if(web.goal!=null)for(PhoneObservation.Node row:graph.rows)if("android.widget.Button".equals(row.className)
                            &&WebFlightNativeStability.LABEL.equals(row.label())&&row.nativeTreePath!=null){
                        if(target!=null)return null;target=row;
                    }
                    if(target==null||graph.refs.get(target.id)==null)return null;
                    Graph copy=graph.copyForAction(target.id,null);
                    try{return new FlightObservationSnapshot(HeptaAccessibilityService.this,web,taskBackground,taskScope,
                            taskAuthorization,frame,copy,target.id,target.nativeTreePath,SystemClock.elapsedRealtime(),null);}
                    catch(RuntimeException failure){copy.close();throw failure;}
                }
            }
        },cancel,deadline);
        if(source==null)return null;
        boolean accepted=false;
        try{
            requireFlightObservationAuthority(web,source,frame,cancel,deadline);
            source.sealFrame(org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(frame.toJson()));
            requireCompleteFlightSnapshot(source);requireFlightObservationLive(web,source,frame,cancel,deadline);
            accepted=true;return source;
        }finally{if(!accepted)source.close();}
    }
    JSONObject verifyFlightObservationBracket(final WebFlightSession web,final FlightObservationSnapshot source,
            final PhoneObservation after,final WebEvidenceReceipt first,final WebEvidenceReceipt last,
            final Cancellation cancel,final long deadline)throws Exception{
        requireFlightObservationAuthority(web,source,after,cancel,deadline);
        final FlightObservationSnapshot observed=retainFlightObservation(web,after,cancel,deadline);
        if(observed==null)throw new StaleObservation("Flight只读复核缺少新的完整原生目标");
        FlightObservationSnapshot sourceCopy=null,observedCopy=null;boolean ownershipTransferred=false;
        try{
            sourceCopy=source.copyForRead();observedCopy=observed.copyForRead();
            final FlightObservationSnapshot ownedSource=sourceCopy,ownedObserved=observedCopy;
            if(!observationIoBusy.compareAndSet(false,true))throw new StaleObservation("先前屏幕读取尚未真实退出");
            final Runnable cleanup=new Runnable(){public void run(){
                try{ownedSource.close();}finally{try{ownedObserved.close();}finally{observationIoBusy.set(false);}}
            }};
            final GraphBudget budget=new GraphBudget(){public void check(){
                requireFlightObservationLive(web,source,after,cancel,deadline);
                requireFlightObservationLive(web,observed,after,cancel,deadline);
            }};
            FlightObservationRead<JSONObject> call=new FlightObservationRead<JSONObject>(new java.util.concurrent.Callable<JSONObject>(){
                public JSONObject call()throws Exception{
                    return verifyFlightObservationOnWorker(web,ownedSource,ownedObserved,after,first,last,cancel,deadline,budget);
                }
            },cancel,deadline,cleanup);
            // Unexpected submission failure keeps capacity fenced; only definitive rejection proves no read entered.
            ownershipTransferred=true;
            try{observationIo.execute(call);}
            catch(java.util.concurrent.RejectedExecutionException rejected){cleanup.run();throw rejected;}
            JSONObject result=call.await();
            requireFlightObservationAuthority(web,source,after,cancel,deadline);
            requireFlightObservationAuthority(web,observed,after,cancel,deadline);
            return result;
        }finally{
            observed.close();
            if(!ownershipTransferred){if(sourceCopy!=null)sourceCopy.close();if(observedCopy!=null)observedCopy.close();}
        }
    }
    private JSONObject verifyFlightObservationOnWorker(WebFlightSession web,FlightObservationSnapshot source,
            FlightObservationSnapshot observedSource,PhoneObservation after,WebEvidenceReceipt first,WebEvidenceReceipt last,
            Cancellation cancel,long deadline,GraphBudget budget)throws Exception{
        if(Looper.myLooper()==Looper.getMainLooper())throw new IllegalStateException("Flight native traversal must stay off main");
        checkReadBudget(budget);requireFlightObservationAuthority(web,source,after,cancel,deadline);
        requireFlightObservationAuthority(web,observedSource,after,cancel,deadline);
        long started=SystemClock.elapsedRealtime();Graph observed=observedSource.graph,liveGraph=null;
        requireCompleteFlightSnapshot(source);requireCompleteFlightSnapshot(observedSource);
        if(!java.util.Objects.equals(source.ownerSha,observed.backgroundOwnerSha)
                ||!java.util.Objects.equals(source.selectionRaw,observed.backgroundSelectionRaw)
                ||!source.targetPath.equals(observedSource.targetPath))
            throw new StaleObservation("Flight只读观察来源不属于当前任务或同一完整原生目标");
        if(!"captured".equals(first.status)||!"captured".equals(last.status)
                ||!first.bindingSha.equals(last.bindingSha)||source.frame.capturedElapsedMillis>source.retainedAt
                ||source.retainedAt>first.started||first.ended>after.capturedElapsedMillis
                ||after.capturedElapsedMillis>last.started||last.ended>started)
            throw new StaleObservation("Flight只读观察与真实capture时序不同");
        JSONObject firstCapture=first.capture(),lastCapture=last.capture(),binding=firstCapture.getJSONObject("binding");
        if(!web.taskId.equals(binding.getString("task_id"))||!source.ownerSha.equals(binding.getString("owner_sha256"))
                ||!source.authorization.authorization.sha256.equals(binding.getJSONObject("authorization").getString("authorization_sha256")))
            throw new StaleObservation("Flight只读capture的任务或OWNER来源不同");
        JSONArray beforeNative=new JSONArray(source.graph.flightNativeSnapshotRaw);
        JSONArray observedNative=new JSONArray(observed.flightNativeSnapshotRaw);
        JSONObject proof=web.purpose.shopping!=null
                ?WebShoppingObservationStability.compareObservationBracket(web.taskId,new JSONObject(source.frameRaw),
                        beforeNative,new JSONObject(observedSource.frameRaw),observedNative,firstCapture,lastCapture,source.targetPath)
                :WebFlightNativeStability.compareObservationBracket(web.taskId,new JSONObject(source.frameRaw),
                        beforeNative,new JSONObject(observedSource.frameRaw),observedNative,firstCapture,lastCapture,source.targetPath);
        try{
            checkReadBudget(budget);liveGraph=readGraph(budget,source.background);checkReadBudget(budget);
            if(!completeFlightGraph(liveGraph)||!observed.sameWindow(liveGraph)
                    ||!observed.windowMetadata.bindFreshness("").equals(liveGraph.windowMetadata.bindFreshness("")))
                throw new StaleObservation("Flight只读观察最后完整图或窗口已变化");
            JSONArray liveNative=new JSONArray(liveGraph.flightNativeSnapshotRaw);
            JSONArray observedRows=new JSONArray(observed.flightRetainedSnapshotRaw),liveRows=new JSONArray(liveGraph.flightRetainedSnapshotRaw);
            if(liveNative.length()!=liveGraph.collectionStats.visited||liveRows.length()!=liveGraph.collectionStats.retained)
                throw new StaleObservation("Flight最后完整树与保留节点计数不匹配");
            JSONObject liveProof;
            if(web.purpose.shopping!=null){
                liveProof=WebShoppingObservationStability.compareNative(observedNative,liveNative,source.targetPath);
                liveProof.put("retained_node_pairing",WebShoppingObservationStability.compareRetained(observedRows,liveRows,
                        liveProof.getString("recommendation_native_path")));
            }else{
                liveProof=WebFlightNativeStability.compareNative(observedNative,liveNative,source.targetPath);
                liveProof.put("retained_node_pairing",WebFlightNativeStability.compareRetained(observedRows,liveRows,
                        liveProof.getString("native_slider_path")));
            }
            NodeRef liveTarget=null;
            for(PhoneObservation.Node row:liveGraph.rows)if(source.targetPath.equals(row.nativeTreePath)){
                if(liveTarget!=null)throw new StaleObservation("Flight最后目标不唯一");liveTarget=liveGraph.refs.get(row.id);
            }
            if(liveTarget==null||!source.original.node.equals(observedSource.original.node)
                    ||!source.original.node.equals(liveTarget.node)||!source.original.signature.equals(observedSource.original.signature)
                    ||!source.original.signature.equals(liveTarget.signature))
                throw new StaleObservation("Flight原始目标身份或签名已变化");
            checkReadBudget(budget);Rect box=new Rect();source.original.node.getBoundsInScreen(box);
            int[] region={box.left,box.top,box.right,box.bottom};
            JSONObject windowsBefore=readFlightObservationWindows(after,first.displayId,first.windowId,region,budget);
            refreshFlightObservationTargetChain(source.background,after,source.original,source.targetPath,beforeNative,budget);
            if(!source.original.signature.equals(nodeSignature(source.original.node,observedChildText(source.original.node,true,budget))))
                throw new StaleObservation("Flight观察目标最后刷新签名已变化");
            checkReadBudget(budget);
            JSONObject windowsAfter=readFlightObservationWindows(after,first.displayId,first.windowId,region,budget);
            if(!org.trillionnium.hepta.webprotocol.WebDomCanonical.same(windowsBefore,windowsAfter))
                throw new StaleObservation("Flight观察期间交互窗口覆盖元数据变化");
            requireFlightObservationAuthority(web,source,after,cancel,deadline);
            requireFlightObservationAuthority(web,observedSource,after,cancel,deadline);checkReadBudget(budget);
            return proof.put("source","private_service_snapshot_and_live_complete_native_traversal")
                    .put("original_target_obtained_before_graph_recycling",true)
                    .put("original_node_ref_identity_preserved",true).put("actual_ancestor_chain_refreshed",true)
                    .put("source_retained_elapsed_ms",source.retainedAt)
                    .put("first_ax_captured_elapsed_ms",source.frame.capturedElapsedMillis)
                    .put("last_ax_captured_elapsed_ms",after.capturedElapsedMillis)
                    .put("started_elapsed_ms",started).put("checked_elapsed_ms",SystemClock.elapsedRealtime())
                    .put("live_native_recheck",liveProof).put("interactive_windows_before",windowsBefore)
                    .put("interactive_windows_after",windowsAfter).put("two_interactive_window_reads_equal",true)
                    .put("native_invocation_entered",false);
        }finally{if(liveGraph!=null)liveGraph.close();}
    }

    private void refreshFlightObservationTargetChain(BackgroundSession background,PhoneObservation frame,NodeRef original,
                                         String targetPath,JSONArray snapshot,GraphBudget budget)throws Exception{
        checkReadBudget(budget);
        java.util.Map<String,JSONObject> records=new java.util.HashMap<String,JSONObject>();
        for(int i=0;i<snapshot.length();i++){JSONObject row=snapshot.getJSONObject(i);records.put(row.getString("path"),row);}
        java.util.List<AccessibilityNodeInfo> owned=new java.util.ArrayList<AccessibilityNodeInfo>();
        AccessibilityNodeInfo cursor=original.node;String path=targetPath;
        Rect target=new Rect();cursor.getBoundsInScreen(target);
        try{
            for(int depth=0;depth<64;depth++){
                checkReadBudget(budget);JSONObject expected=records.get(path);
                if(expected==null||!refreshFlightObservationNode(budget,cursor)||!cursor.isVisibleToUser()||!cursor.isEnabled()||cursor.isPassword())
                    throw new StaleObservation("首页目标祖先不可用");
                checkReadBudget(budget);requireBackgroundNodeWindow(background,frame,cursor);checkReadBudget(budget);
                Rect actual=new Rect();cursor.getBoundsInScreen(actual);
                if(!actual.contains(target)||!org.trillionnium.hepta.webprotocol.WebDomCanonical.same(expected,
                        snapshotFlightNode(cursor,path,expected.getString("parent_class"))))
                    throw new StaleObservation("首页目标祖先或原生几何已变化");
                AccessibilityNodeInfo parent=flightObservationParent(budget,cursor,owned);
                if("0".equals(path)){
                    if(parent!=null)throw new StaleObservation("首页原生根边界变化");return;
                }
                int slash=path.lastIndexOf('/'),index=Integer.parseInt(path.substring(slash+1));
                if(parent==null||!refreshFlightObservationNode(budget,parent)||index>=parent.getChildCount()
                        ||!expected.getString("parent_class").equals(string(parent.getClassName())))
                    throw new StaleObservation("首页目标父节点关系变化");
                AccessibilityNodeInfo child=flightObservationChild(budget,parent,index,owned);
                if(child==null||!refreshFlightObservationNode(budget,child)||!child.equals(cursor))throw new StaleObservation("首页目标父子身份变化");
                cursor=parent;path=path.substring(0,slash);
            }
            throw new StaleObservation("首页原生祖先预算不足");
        }finally{for(AccessibilityNodeInfo node:owned)node.recycle();}
    }

    private boolean refreshFlightObservationNode(GraphBudget budget,AccessibilityNodeInfo node){
        checkReadBudget(budget);boolean refreshed=node.refresh();checkReadBudget(budget);return refreshed;
    }
    private AccessibilityNodeInfo flightObservationParent(GraphBudget budget,AccessibilityNodeInfo child,List<AccessibilityNodeInfo> owned){
        checkReadBudget(budget);AccessibilityNodeInfo parent=child.getParent();
        if(parent!=null)owned.add(parent);checkReadBudget(budget);return parent;
    }
    private AccessibilityNodeInfo flightObservationChild(GraphBudget budget,AccessibilityNodeInfo parent,int index,List<AccessibilityNodeInfo> owned){
        checkReadBudget(budget);AccessibilityNodeInfo child=parent.getChild(index);
        if(child!=null)owned.add(child);checkReadBudget(budget);return child;
    }

    private JSONObject readFlightObservationWindows(PhoneObservation frame,int displayId,int windowId,int[] region,GraphBudget budget)throws Exception{
        checkReadBudget(budget);checkReadBudget(budget);AccessibilityServiceInfo info=getServiceInfo();checkReadBudget(budget);
        if(info==null||(info.flags&AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS)==0
                ||(info.getCapabilities()&AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT)==0)
            throw new StaleObservation("原生窗口覆盖元数据不可用");
        List<AccessibilityWindowInfo> windows=windowsForDisplay(displayId);
        if(windows==null)throw new StaleObservation("原生窗口集合不可用");
        try{
            checkReadBudget(budget);
            if(windows.isEmpty()||windows.size()>64)throw new StaleObservation("原生窗口集合不可用");
            java.util.TreeMap<Integer,JSONObject> rows=new java.util.TreeMap<Integer,JSONObject>();
            int targetLayer=-1;Rect targetBounds=null;
            for(AccessibilityWindowInfo window:windows){
                checkReadBudget(budget);
                if(window==null||window.getDisplayId()!=displayId||window.getId()<0
                        ||window.getType()<=0||window.getLayer()<0)
                    throw new StaleObservation("原生窗口身份缺失");
                Rect bounds=new Rect();window.getBoundsInScreen(bounds);
                if(bounds.isEmpty())throw new StaleObservation("原生窗口范围未知");
                JSONObject row=new JSONObject().put("window_id",window.getId()).put("display_id",window.getDisplayId())
                        .put("type",window.getType()).put("layer",window.getLayer())
                        .put("bounds",new JSONArray(new int[]{bounds.left,bounds.top,bounds.right,bounds.bottom}))
                        .put("focused",window.isFocused()).put("active",window.isActive());
                if(rows.put(window.getId(),row)!=null)throw new StaleObservation("原生窗口身份重复");
                if(window.getId()==windowId){
                    if(window.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION)
                        throw new StaleObservation("目标已不是原应用窗口");
                    targetLayer=window.getLayer();targetBounds=new Rect(bounds);
                }
                if(window.getType()==AccessibilityWindowInfo.TYPE_INPUT_METHOD)
                    throw new StaleObservation("商品只读点击时出现输入法窗口");
            }
            int[] expected=frame.windowMetadata.windowBounds();
            Rect anchorBounds=new Rect(region[0],region[1],region[2],region[3]);
            if(targetLayer<0||targetBounds==null||expected==null||expected.length!=4
                    ||targetBounds.left!=expected[0]||targetBounds.top!=expected[1]
                    ||targetBounds.right!=expected[2]||targetBounds.bottom!=expected[3]||!targetBounds.contains(anchorBounds))
                throw new StaleObservation("目标原生窗口或卡片范围已变化");
            for(AccessibilityWindowInfo window:windows)if(window.getId()!=windowId&&window.getLayer()>=targetLayer){
                checkReadBudget(budget);
                Rect bounds=new Rect();window.getBoundsInScreen(bounds);
                if(Rect.intersects(bounds,anchorBounds))throw new StaleObservation("原生商品区域被其它交互窗口覆盖");
            }
            JSONArray ordered=new JSONArray();for(JSONObject row:rows.values())ordered.put(row);checkReadBudget(budget);
            return new JSONObject().put("source","getWindowsOnAllDisplays_selected_display_metadata")
                    .put("display_id",displayId).put("target_window_id",windowId).put("target_layer",targetLayer)
                    .put("target_native_bounds",new JSONArray(region)).put("windows",ordered)
                    .put("observed_upper_or_same_layer_overlap",false).put("ime_window_observed",false)
                    .put("other_window_roots_traversed",false).put("unreported_windows_excluded",false);
        }finally{for(AccessibilityWindowInfo window:windows)if(window!=null)window.recycle();}
    }
    private static String nodeSignature(AccessibilityNodeInfo node,ObservedChildText.Result childText){
        // Capture and target refresh both supply the same bounded subtree observation.
        return readImeEnter(node).bindFreshness(readScrollActions(node).bindFreshness(childText.bind(baseNodeSignature(node))),node.isFocused(),inputTextHash(node));
    }
    private static String inputTextHash(AccessibilityNodeInfo node){
        if(!node.isEditable()||node.isPassword())return null;
        CharSequence text=node.getText();
        return ObservedImeEnter.completeTextHash(text==null?null:text.toString());
    }
    /** A final read-only recheck of actual native references. No coordinate input,
     * new window, page script, permission change, or additional ARM is issued. */
    private NativeRegionCheck requireLiveNativeRegion(String taskId,PhoneObservation frame,AccessibilityNodeInfo clicked,
            WebRegionNativeBridge bridge,Cancellation cancel,ActionWork work)throws Exception{
        actionPhase(work,"graph_read");actionCheck(work);Graph graph=graphForAction(work);
        long started=SystemClock.elapsedRealtime();BackgroundSession background=backgroundFor(taskId);
        if(background==null||cancel.isCancelled()||!owns(taskId)||frame!=current||graph==null
                ||work!=null&&work.nativeRegion!=bridge)
            throw new StaleObservation("商品原生复核的任务或观察已失效");
        requireBackgroundObservation(taskId,frame);background.requireActive();bridge.requireFrame(frame);
        actionCheck(work);
        if(graph.windowId!=bridge.windowId||graph.displayId!=bridge.displayId
                ||!bridge.generation.equals(graph.backgroundGeneration))
            throw new StaleObservation("商品原生复核的屏幕或窗口已变化");
        NodeRef anchorRef=graph.refs.get(bridge.anchor.id),webRef=graph.refs.get(bridge.nativeWebViewId);
        if(anchorRef==null||anchorRef.node!=clicked||webRef==null)
            throw new StaleObservation("商品点击没有原始原生节点引用");
        for(WebRegionNativeBridge.Role role:bridge.roles())refreshRegionRole(background,frame,role,work);
        if(!refreshActionNode(work,webRef.node)||!webRef.node.isVisibleToUser()||!webRef.node.isEnabled()
                ||!bridge.nativeWebViewSignature.equals(observedChildText(webRef.node,true,work==null?null:work.budget()).bind(baseNodeSignature(webRef.node))))
            throw new StaleObservation("原生 WebView 祖先已变化");
        actionCheck(work);requireBackgroundNodeWindow(background,frame,webRef.node);actionCheck(work);
        List<AccessibilityNodeInfo> temporary=new ArrayList<AccessibilityNodeInfo>();
        try{
            // These child positions are independently observed native relations,
            // never DOM paths or a screen-coordinate mapping.
            if(clicked.getChildCount()!=5)throw new StaleObservation("商品原生子树结构不再匹配实际样本");
            AccessibilityNodeInfo model=regionChild(work,clicked,1,temporary);
            AccessibilityNodeInfo prices=regionChild(work,clicked,2,temporary);
            if(model==null||prices==null||!refreshActionNode(work,model)||!refreshActionNode(work,prices)||prices.getChildCount()!=2
                    ||!"android.view.View".equals(string(prices.getClassName())))
                throw new StaleObservation("商品名称或同组价格容器已变化");
            AccessibilityNodeInfo currentPrice=regionChild(work,prices,0,temporary);
            AccessibilityNodeInfo comparisonPrice=regionChild(work,prices,1,temporary);
            List<WebRegionNativeBridge.Role> roles=bridge.roles();
            if(currentPrice==null||comparisonPrice==null||!refreshActionNode(work,currentPrice)||!refreshActionNode(work,comparisonPrice)
                    ||!model.equals(graph.refs.get(roles.get(1).nodeId).node)
                    ||!currentPrice.equals(graph.refs.get(roles.get(2).nodeId).node)
                    ||!comparisonPrice.equals(graph.refs.get(roles.get(3).nodeId).node))
                throw new StaleObservation("同组商品四角色的原生节点身份不再一致");
            AccessibilityNodeInfo modelParent=regionParent(work,model,temporary);
            AccessibilityNodeInfo pricesParent=regionParent(work,prices,temporary);
            AccessibilityNodeInfo currentParent=regionParent(work,currentPrice,temporary);
            AccessibilityNodeInfo comparisonParent=regionParent(work,comparisonPrice,temporary);
            if(modelParent==null||pricesParent==null||currentParent==null||comparisonParent==null
                    ||!refreshActionNode(work,modelParent)||!refreshActionNode(work,pricesParent)
                    ||!refreshActionNode(work,currentParent)||!refreshActionNode(work,comparisonParent)
                    ||!modelParent.equals(clicked)||!pricesParent.equals(clicked)
                    ||!currentParent.equals(prices)||!comparisonParent.equals(prices))
                throw new StaleObservation("商品原生父子关系已变化");
            int distance=bridge.anchor.nativeTreePath.split("/").length-bridge.nativeWebViewPath.split("/").length;
            if(distance<1||distance>64)throw new StaleObservation("商品到原生 WebView 的祖先关系不可证明");
            AccessibilityNodeInfo cursor=clicked;
            Rect anchorBounds=new Rect();clicked.getBoundsInScreen(anchorBounds);
            for(int depth=1;depth<=distance;depth++){
                AccessibilityNodeInfo parent=regionParent(work,cursor,temporary);
                if(parent==null||!refreshActionNode(work,parent)||!parent.isVisibleToUser()||!parent.isEnabled()||parent.isPassword()
                        ||!frame.packageName.equals(string(parent.getPackageName()))||parent.getWindowId()!=frame.windowId)
                    throw new StaleObservation("商品原生祖先不可用或越出绑定窗口");
                actionCheck(work);requireBackgroundNodeWindow(background,frame,parent);actionCheck(work);
                Rect bounds=new Rect();parent.getBoundsInScreen(bounds);
                if(bounds.isEmpty()||!bounds.contains(anchorBounds)
                        ||depth==1&&!bridge.anchor.nativeParentClass.equals(string(parent.getClassName())))
                    throw new StaleObservation("商品原生祖先范围或类型已变化");
                boolean isWebView="android.webkit.WebView".equals(string(parent.getClassName()));
                if(depth<distance&&isWebView||depth==distance&&(!isWebView||!parent.equals(webRef.node)))
                    throw new StaleObservation("商品不再位于同一实际 WebView 祖先");
                cursor=parent;
            }
        }finally{
            for(AccessibilityNodeInfo node:temporary)if(node!=null)node.recycle();
        }
        JSONObject windowsBefore=readRegionWindows(frame,bridge,work);
        for(WebRegionNativeBridge.Role role:bridge.roles())refreshRegionRole(background,frame,role,work);
        JSONObject windowsAfter=readRegionWindows(frame,bridge,work);
        if(!org.trillionnium.hepta.webprotocol.WebDomCanonical.same(windowsBefore,windowsAfter))
            throw new StaleObservation("商品点击前的原生窗口覆盖关系已变化");
        background.requireActive();actionCheck(work);
        if(cancel.isCancelled()||!owns(taskId)||frame!=current)throw new StaleObservation("商品任务已退休");
        return new NativeRegionCheck(frame,bridge,started,SystemClock.elapsedRealtime(),windowsAfter);
    }
    private AccessibilityNodeInfo regionChild(ActionWork work,AccessibilityNodeInfo parent,int index,List<AccessibilityNodeInfo> temporary){
        actionCheck(work);AccessibilityNodeInfo child=parent.getChild(index);
        if(child!=null)temporary.add(child);actionCheck(work);return child;
    }
    private AccessibilityNodeInfo regionParent(ActionWork work,AccessibilityNodeInfo child,List<AccessibilityNodeInfo> temporary){
        actionCheck(work);AccessibilityNodeInfo parent=child.getParent();
        if(parent!=null)temporary.add(parent);actionCheck(work);return parent;
    }
    private void refreshRegionRole(BackgroundSession background,PhoneObservation frame,WebRegionNativeBridge.Role role,ActionWork work){
        actionCheck(work);Graph graph=graphForAction(work);NodeRef ref=graph==null?null:graph.refs.get(role.nodeId);
        if(ref==null||!role.nodeSignature.equals(ref.appTreeSignature)||!refreshActionNode(work,ref.node))
            throw new StaleObservation("商品原生角色引用已变化："+role.role);
        AccessibilityNodeInfo node=ref.node;ObservedChildText.Result child=observedChildText(node,true,work==null?null:work.budget());
        Rect bounds=new Rect();node.getBoundsInScreen(bounds);int[] expected=role.bounds();
        if(!ref.signature.equals(nodeSignature(node,child))||!node.isVisibleToUser()||!node.isEnabled()
                ||!role.packageName.equals(string(node.getPackageName()))||!role.className.equals(string(node.getClassName()))
                ||!role.viewId.equals(string(node.getViewIdResourceName()))||!role.text.equals(string(node.getText()))
                ||!role.description.equals(string(node.getContentDescription()))||node.isClickable()!=role.clickable
                ||node.isEditable()!=role.editable||node.isScrollable()!=role.scrollable||node.isFocused()!=role.focused
                ||node.isPassword()!=role.password||bounds.left!=expected[0]||bounds.top!=expected[1]
                ||bounds.right!=expected[2]||bounds.bottom!=expected[3])
            throw new StaleObservation("商品原生角色内容或几何已变化："+role.role);
        actionCheck(work);requireBackgroundNodeWindow(background,frame,node);actionCheck(work);
    }
    /** Metadata-only; no root or text is read from any other application/window. */
    private JSONObject readRegionWindows(PhoneObservation frame,WebRegionNativeBridge bridge,ActionWork work)throws Exception{
        return readRegionWindows(frame,bridge.displayId,bridge.windowId,bridge.anchorBounds(),work);
    }
    private JSONObject readRegionWindows(PhoneObservation frame,int displayId,int windowId,int[] region,ActionWork work)throws Exception{
        actionPhase(work,"scope_read");actionCheck(work);AccessibilityServiceInfo info=getServiceInfo();actionCheck(work);
        if(info==null||(info.flags&AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS)==0
                ||(info.getCapabilities()&AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT)==0)
            throw new StaleObservation("原生窗口覆盖元数据不可用");
        List<AccessibilityWindowInfo> windows=windowsForDisplay(displayId);
        if(windows==null)throw new StaleObservation("原生窗口集合不可用");
        try{
            actionCheck(work);
            if(windows.isEmpty()||windows.size()>64)throw new StaleObservation("原生窗口集合不可用");
            java.util.TreeMap<Integer,JSONObject> rows=new java.util.TreeMap<Integer,JSONObject>();
            int targetLayer=-1;Rect targetBounds=null;
            for(AccessibilityWindowInfo window:windows){
                actionCheck(work);
                if(window==null||window.getDisplayId()!=displayId||window.getId()<0
                        ||window.getType()<=0||window.getLayer()<0)
                    throw new StaleObservation("原生窗口身份缺失");
                Rect bounds=new Rect();window.getBoundsInScreen(bounds);
                if(bounds.isEmpty())throw new StaleObservation("原生窗口范围未知");
                JSONObject row=new JSONObject().put("window_id",window.getId()).put("display_id",window.getDisplayId())
                        .put("type",window.getType()).put("layer",window.getLayer())
                        .put("bounds",new JSONArray(new int[]{bounds.left,bounds.top,bounds.right,bounds.bottom}))
                        .put("focused",window.isFocused()).put("active",window.isActive());
                if(rows.put(window.getId(),row)!=null)throw new StaleObservation("原生窗口身份重复");
                if(window.getId()==windowId){
                    if(window.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION)
                        throw new StaleObservation("目标已不是原应用窗口");
                    targetLayer=window.getLayer();targetBounds=new Rect(bounds);
                }
                if(window.getType()==AccessibilityWindowInfo.TYPE_INPUT_METHOD)
                    throw new StaleObservation("商品只读点击时出现输入法窗口");
            }
            int[] expected=frame.windowMetadata.windowBounds();
            Rect anchorBounds=new Rect(region[0],region[1],region[2],region[3]);
            if(targetLayer<0||targetBounds==null||expected==null||expected.length!=4
                    ||targetBounds.left!=expected[0]||targetBounds.top!=expected[1]
                    ||targetBounds.right!=expected[2]||targetBounds.bottom!=expected[3]||!targetBounds.contains(anchorBounds))
                throw new StaleObservation("目标原生窗口或卡片范围已变化");
            for(AccessibilityWindowInfo window:windows)if(window.getId()!=windowId&&window.getLayer()>=targetLayer){
                actionCheck(work);
                Rect bounds=new Rect();window.getBoundsInScreen(bounds);
                if(Rect.intersects(bounds,anchorBounds))throw new StaleObservation("原生商品区域被其它交互窗口覆盖");
            }
            JSONArray ordered=new JSONArray();for(JSONObject row:rows.values())ordered.put(row);actionCheck(work);
            return new JSONObject().put("source","getWindowsOnAllDisplays_selected_display_metadata")
                    .put("display_id",displayId).put("target_window_id",windowId).put("target_layer",targetLayer)
                    .put("target_native_bounds",new JSONArray(region)).put("windows",ordered)
                    .put("observed_upper_or_same_layer_overlap",false).put("ime_window_observed",false)
                    .put("other_window_roots_traversed",false).put("unreported_windows_excluded",false);
        }finally{for(AccessibilityWindowInfo window:windows)if(window!=null)window.recycle();}
    }
    private static void requireSubmitWindow(AccessibilityNodeInfo node,int windowId,int displayId){
        AccessibilityWindowInfo window=node.getWindow();
        try{
            if(window==null||window.getId()!=windowId||window.getDisplayId()!=displayId||window.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION)
                throw new IllegalStateException("查询提交节点已移出绑定应用窗口或屏幕");
        }finally{if(window!=null)window.recycle();}
    }
    private static ObservedImeEnter readImeEnter(AccessibilityNodeInfo node){
        try{
            List<AccessibilityNodeInfo.AccessibilityAction> actions=node.getActionList();
            if(actions==null||actions.size()>128)return ObservedImeEnter.UNKNOWN;
            ObservedImeEnter result=ObservedImeEnter.ABSENT;boolean found=false;
            for(AccessibilityNodeInfo.AccessibilityAction action:actions){
                if(action==null)return ObservedImeEnter.UNKNOWN;
                if(action.getId()==AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.getId()){
                    if(found)return ObservedImeEnter.UNKNOWN;found=true;
                    CharSequence label=action.getLabel();result=ObservedImeEnter.present(label==null?null:label.toString());
                }
            }
            return result;
        }catch(RuntimeException unavailable){return ObservedImeEnter.UNKNOWN;}
    }
    /** No aliasing of logical forward/backward to content directions. */
    private static ObservedScrollActions readScrollActions(AccessibilityNodeInfo node){
        try{
            List<AccessibilityNodeInfo.AccessibilityAction> actions=node.getActionList();
            if(actions==null||actions.size()>128)return ObservedScrollActions.UNKNOWN;
            List<String> directions=new ArrayList<String>();
            for(AccessibilityNodeInfo.AccessibilityAction action:actions){
                if(action==null)return ObservedScrollActions.UNKNOWN;
                int id=action.getId();
                if(id==AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_FORWARD.getId())directions.add("forward");
                else if(id==AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_BACKWARD.getId())directions.add("backward");
                else if(id==AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_UP.getId())directions.add("up");
                else if(id==AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_DOWN.getId())directions.add("down");
                else if(id==AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_LEFT.getId())directions.add("left");
                else if(id==AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_RIGHT.getId())directions.add("right");
            }
            return ObservedScrollActions.observed(directions);
        }catch(RuntimeException unavailable){return ObservedScrollActions.UNKNOWN;}
    }
    private static ObservedChildText.Result observedChildText(final AccessibilityNodeInfo root){return observedChildText(root,false);}
    private static ObservedChildText.Result observedChildText(final AccessibilityNodeInfo root,final boolean refreshChildren){return observedChildText(root,refreshChildren,null);}
    private static ObservedChildText.Result observedChildText(final AccessibilityNodeInfo root,final boolean refreshChildren,final GraphBudget budget){
        checkReadBudget(budget);
        final Rect rootBounds=new Rect();root.getBoundsInScreen(rootBounds);
        final String ownerPackage=string(root.getPackageName());final int ownerWindow=root.getWindowId();
        final boolean[] staleChild={false};
        ObservedChildText.Result result=ObservedChildText.collect(root,new ObservedChildText.Reader<AccessibilityNodeInfo>(){
            public ObservedChildText.Metadata metadata(AccessibilityNodeInfo node){
                checkReadBudget(budget);
                if(refreshChildren&&node!=root&&!node.refresh()){
                    staleChild[0]=true;throw new StaleObservation("后台标签子节点已不可用，需重新观察");
                }
                checkReadBudget(budget);Rect bounds=new Rect();node.getBoundsInScreen(bounds);
                boolean inputLike=node.isEditable()||node.getInputType()!=0;
                boolean clickAction=hasAction(node,AccessibilityNodeInfo.ACTION_CLICK);
                boolean interactive=node.isClickable()||node.isLongClickable()||inputLike||node.isScrollable()||node.isCheckable()
                        ||clickAction||hasAction(node,AccessibilityNodeInfo.ACTION_LONG_CLICK)
                        ||hasAction(node,AccessibilityNodeInfo.ACTION_SET_TEXT)
                        ||hasAction(node,AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)||hasAction(node,AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD)
                        ||hasAction(node,AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_UP.getId())
                        ||hasAction(node,AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_DOWN.getId())
                        ||hasAction(node,AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_LEFT.getId())
                        ||hasAction(node,AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_RIGHT.getId());
                return new ObservedChildText.Metadata(node.isVisibleToUser()&&!bounds.isEmpty(),
                        ownerWindow==node.getWindowId()&&ownerPackage.equals(string(node.getPackageName()))&&Rect.intersects(rootBounds,bounds),
                        node.isClickable(),clickAction,inputLike,node.isPassword(),interactive);
            }
            // collect() checks metadata boundaries before calling either text accessor.
            public String text(AccessibilityNodeInfo node){return string(node.getText());}
            public String description(AccessibilityNodeInfo node){return string(node.getContentDescription());}
            public String identity(AccessibilityNodeInfo node){return baseNodeSignature(node);}
            public String viewId(AccessibilityNodeInfo node){return string(node.getViewIdResourceName());}
            public int childCount(AccessibilityNodeInfo node){return node.getChildCount();}
            public AccessibilityNodeInfo child(AccessibilityNodeInfo node,int index){checkReadBudget(budget);return node.getChild(index);}
            public void release(AccessibilityNodeInfo node){node.recycle();}
        });
        // collect() intentionally suppresses inaccessible child labels; a failed live
        // refresh additionally invalidates this background frame, not just its label.
        checkReadBudget(budget);
        if(staleChild[0])throw new StaleObservation("后台标签子节点已不可用，需重新观察");
        return result;
    }
    private static String baseNodeSignature(AccessibilityNodeInfo node){
        Rect bounds=new Rect();node.getBoundsInScreen(bounds);
        String value=string(node.getPackageName())+"\u0001"+node.getWindowId()+"\u0001"+string(node.getClassName())+"\u0001"+string(node.getViewIdResourceName())+"\u0001"+bounds+"\u0001"+
                (node.isPassword()?"<password>":string(node.getText())+"\u0001"+string(node.getContentDescription()))+"\u0001"+node.isEnabled()+"|"+node.isClickable()+"|"+node.isEditable()+"|"+node.isScrollable();
        return sha(value.getBytes(StandardCharsets.UTF_8));
    }
    static String sha(byte[] raw){try{MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] bytes=digest.digest(raw);StringBuilder value=new StringBuilder();for(byte b:bytes)value.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return value.toString();}catch(Exception e){throw new IllegalStateException(e);}}
    private static String fileSha256(File file)throws Exception{MessageDigest digest=MessageDigest.getInstance("SHA-256");try(java.io.FileInputStream stream=new java.io.FileInputStream(file)){byte[] buffer=new byte[65536];int size;while((size=stream.read(buffer))!=-1)digest.update(buffer,0,size);}StringBuilder value=new StringBuilder();for(byte b:digest.digest())value.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return value.toString();}
    private static String string(CharSequence value){return value==null?"":value.toString();}
    static String limited(String text,int max){if(text.length()<=max)return text;int end=max;if(end>0&&Character.isHighSurrogate(text.charAt(end-1)))end--;return text.substring(0,end)+"…";}
    static String message(Throwable e){String value=e.getMessage();return value==null?e.getClass().getSimpleName():limited(value,300);}
}
