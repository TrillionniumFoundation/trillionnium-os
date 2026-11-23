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
import android.graphics.Region;
import android.os.Parcel;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;
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
import java.util.LinkedHashMap;
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
        // Separate pure-value channel; only failed task finalization may persist it.
        default void onPrivateCensusDiagnostic(java.util.concurrent.Callable<String> snapshot) {}
        // A failed read is never an observation or an action. Old consumers still fail.
        default void onReadRetryAvailable(String error,NativeObservationRetryProof proof){onError(error);}
        default void onInitialReadRetryAvailable(String error,InitialObservationRetryProof proof){onError(error);}
        default void onPostEffectReadRetryAvailable(String error,PostEffectObservationRetryProof proof){onError(error);}
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
    private final ProfilePermissionUiSession profilePermissionUi=new ProfilePermissionUiSession(this);
    private Runnable stopListener;
    private LocalTaskController ownedController;
    // Actual task read admissions, independent of optional diagnostic sequence numbers.
    private int taskObservationAdmissions;
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
        int type=event.getEventType();
        boolean content=type==AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED
                ||type==AccessibilityEvent.TYPE_VIEW_SCROLLED||type==AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED;
        noteObservationEvent(android.os.Build.VERSION.SDK_INT>=33?event.getDisplayId():-1,
                event.getWindowId(),string(event.getPackageName()),content);
    }
    @Override public void onInterrupt() {
        requestStop();
        String searchTask=lease;if(searchTask!=null)retireNativeSearch(searchTask,"cancelled");
        if(activeObservation!=null)failObservation(activeObservation,"无障碍服务已中断");
    }
    @Override public void onDestroy() {
        String searchTask=lease;if(searchTask!=null)retireNativeSearch(searchTask,"service_destroyed");
        String permissionTask=lease;if(permissionTask!=null)profilePermissionUi.retire(permissionTask,"service_destroyed");
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
        return taskController(new RuntimeInferenceAdapter(this,engine));
    }
    /** Pure idle query for local configuration; no controller retirement or recovery authority. */
    synchronized boolean modelSettingsIdle(){
        if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("settings service check must run on main");
        return live==this&&lease==null&&(ownedController==null||!ownedController.isRunning())
                &&activeObservation==null&&activeNativeSearchObservation==null&&!capturePending&&!observationReadWorkPending()&&!actionWorkPending()&&!nativeCancellationWorkPending()
                &&(taskBackground==null||taskBackground.released())&&(taskWeb==null||taskWeb.released());
    }
    /** Administrative retirement only; no action, inference, capture or old task is restarted. */
    synchronized boolean recoveryControllerIdle(LocalTaskController expected){
        if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("recovery service check must run on main thread");
        return live==this&&ownedController==expected&&(expected==null||!expected.isRunning())
                &&activeObservation==null&&activeNativeSearchObservation==null&&!capturePending&&!observationReadWorkPending()&&!actionWorkPending()&&!nativeCancellationWorkPending()
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
        if(nativeSearchSession!=null)nativeSearchSession.retire();nativeSearchSession=null;nativeSearchPlanningAdmitted=false;
        ownedController=null;lease=null;stopListener=null;appDiscovery=null;taskScope=null;taskBackground=null;taskWeb=null;clearSnapshot();
    }
    private void requestStop() { Runnable value;String task; synchronized(this){value=stopListener;task=lease;}
        discardPostEffectSamplingForTask(task);if(value!=null)value.run(); }
    public synchronized boolean acquireTask(String taskId,Runnable onStop) {
        if(WebFlightSession.hasUnreleased(this))return false;
        synchronized(nativeCancellationQueue.admissionMonitor()){
            if(lease!=null || live!=this||observationReadWorkPending()||actionWorkPending()||nativeCancellationWorkPending())return false;taskWeb=null;lease=taskId;stopListener=onStop;appDiscovery=null;taskScope=null;taskAuthorization=null;taskNotesPhase=null;taskCalculatorInput=null;taskBackground=null;taskSubmitAttempts=null;taskFixedIntentAttempts=null;taskObservationAdmissions=0;return true;
        }
    }
    public synchronized void releaseTask(String taskId) { if(taskId.equals(lease)){
        if(actionWorkPending()||nativeCancellationWorkPending())throw new IllegalStateException("动作或取消工作尚未真实退出，不能释放任务租约");
        if(taskBackground!=null&&!taskBackground.released())throw new IllegalStateException("后台空间未核验释放，不能释放任务租约");
        if(taskWeb!=null&&!taskWeb.released())throw new IllegalStateException("网页工具未核验释放，不能释放任务租约");
        if(nativeSearchSession!=null&&(activeNativeSearchObservation!=null||observationReadWorkPending()))
            throw new IllegalStateException("原生规划读取尚未真实退出，不能释放任务租约");
        discardPostEffectSamplingForTask(taskId);
        retireNativeSearch(taskId,"lease_retired");nativeSearchSession=null;nativeSearchPlanningAdmitted=false;
        taskWeb=null;nativeAxMode=null;
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
    /** The exact background lease chooses its own display scope; foreground keeps its old guard. */
    private boolean locked(BackgroundSession background) {
        if(background==null)return locked();
        if(!ownsBackground(background.taskId,background))return true;
        try{
            if(Looper.myLooper()==Looper.getMainLooper())background.requireAdmissionActive();
            else background.requireActive();
            return false;
        }catch(RuntimeException unavailable){return true;}
    }
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
    ProfilePermissionUiSession permissionUi(){return profilePermissionUi;}
    /** Short captured-identity checks only; suitable for cancellation and node-read budgets. */
    synchronized boolean permissionInitializationCurrent(String id,QualificationScopeConfig.Bound scope,
            TaskAuthorization.Gate authorization,BackgroundSession background){
        return owns(id)&&scope!=null&&taskScope==scope&&authorization!=null&&taskAuthorization==authorization
                &&background!=null&&taskBackground==background&&taskWeb==null&&background.profileTarget()!=null;
    }
    /** The dedicated permission path never calls selectedRoot()/observe(), adds
     * PermissionController to allowedPackages, or lends its receipt to an LLM. */
    void requirePermissionInitializationCurrent(String id,QualificationScopeConfig.Bound scope,
            TaskAuthorization.Gate authorization,BackgroundSession background,Cancellation cancel,long deadline)throws Exception{
        if(Looper.myLooper()==Looper.getMainLooper()||cancel==null||cancel.isCancelled()
                ||SystemClock.elapsedRealtime()>=deadline||!permissionInitializationCurrent(id,scope,authorization,background))
            throw new IllegalStateException("权限准备的原任务、授权、后台租约或期限已退休");
        QualificationScope.require(!scope.restricted(),"permission preparation cannot expand a qualification scope");
        scope.verifyUnchanged();scope.requireReady();authorization.ready();background.requirePermissionPreparationActive();
        if(!authorization.authorization.instructionSha256.equals(background.ownerSha256)||background.displayId()<=1
                ||locked(background)||cancel.isCancelled()||SystemClock.elapsedRealtime()>=deadline
                ||!permissionInitializationCurrent(id,scope,authorization,background))
            throw new IllegalStateException("权限准备的显示、锁状态或原指令身份发生变化");
    }
    void prepareProfilePermissionInitialization(String id,NativeAppGoal goal,TaskAuthorization.Gate authorization,
            BackgroundSession background,File evidence,Cancellation cancel,long deadline)throws Exception{
        QualificationScopeConfig.Bound scope=scopeFor(id);
        requirePermissionInitializationCurrent(id,scope,authorization,background,cancel,deadline);
        if(goal==null||!NativeAppGoal.FLIGHT_RESULTS.equals(goal.kind)
                ||!org.trillionnium.hepta.background.ProfileTarget.CTRIP.equals(goal.packageName)
                ||!goal.ownerSha256.equals(background.ownerSha256)||!goal.ownerSha256.equals(authorization.authorization.instructionSha256)
                ||!goal.packageName.equals(background.profileTarget().packageName)
                ||observationReadWorkPending()||actionSlot.pending()||nativeCancellationWorkPending())
            throw new IllegalStateException("权限初始化只适用于当前原指令绑定的隔离资料查票任务");
        profilePermissionUi.prepare(id,goal,authorization,scope,background,evidence,cancel,deadline);
    }
    JSONObject permissionInitializationEvidence(String id){return profilePermissionUi.evidence(id);}
    JSONObject backgroundEvidence(String id){BackgroundSession background=backgroundFor(id);return background==null?null:background.evidence();}
    /** Read-only worker guard for the narrow prelaunch recovery; it never grants input authority. */
    synchronized boolean prelaunchReconciliationIdle(LocalTaskController expected){
        return live==this&&ownedController==expected&&(expected==null||!expected.isRunning())
                &&activeObservation==null&&activeNativeSearchObservation==null&&!capturePending&&!observationReadWorkPending()&&!actionWorkPending()&&!nativeCancellationWorkPending()
                &&(taskBackground==null||taskBackground.prelaunchRecoveryEligible())
                &&(taskWeb==null||taskWeb.released())
                &&(lease==null||(expected!=null&&lease.equals(expected.currentTaskId())));
    }
    /** The same drained controller gate; this grants only a fresh postlaunch absence check. */
    synchronized boolean postlaunchReconciliationIdle(LocalTaskController expected){
        return live==this&&ownedController==expected&&(expected==null||!expected.isRunning())
                &&activeObservation==null&&activeNativeSearchObservation==null&&!capturePending&&!observationReadWorkPending()&&!actionWorkPending()&&!nativeCancellationWorkPending()
                &&(taskBackground==null||taskBackground.postlaunchRecoveryEligible())
                &&(taskWeb==null||taskWeb.released())
                &&(lease==null||(expected!=null&&lease.equals(expected.currentTaskId())));
    }
    /** Public receipt admission has its own type and eligibility; it grants no action authority. */
    synchronized boolean publicProfileReconciliationIdle(LocalTaskController expected){
        return live==this&&ownedController==expected&&(expected==null||!expected.isRunning())
                &&activeObservation==null&&activeNativeSearchObservation==null&&!capturePending&&!observationReadWorkPending()&&!actionWorkPending()&&!nativeCancellationWorkPending()
                &&(taskBackground==null||taskBackground.publicProfileRecoveryEligible())
                &&(taskWeb==null||taskWeb.released())
                &&(lease==null||(expected!=null&&lease.equals(expected.currentTaskId())));
    }
    /** Current service queues are checked independently of all historical files.
     * Its own checker may be pending; that fact never counts as a model/action worker. */
    synchronized boolean publicProfileBusinessReconciliationIdle(LocalTaskController expected,String task,String owner){
        return task!=null&&task.matches("[0-9a-f]{32}")&&owner!=null&&owner.matches("[0-9a-f]{64}")
                &&live==this&&ownedController==expected&&(expected==null||!expected.isRunning()&&task.equals(expected.currentTaskId()))
                &&activeObservation==null&&activeNativeSearchObservation==null&&!capturePending&&!observationIoBusy.get()&&!actionWorkPending()&&!nativeCancellationWorkPending()
                &&(taskBackground==null||taskBackground.publicProfileRecoveryEligible()&&task.equals(taskBackground.taskId)&&owner.equals(taskBackground.ownerSha256))
                &&(taskWeb==null||taskWeb.released())&&(lease==null||lease.equals(task));
    }
    /** Personal Notes receipt admission has its own type and eligibility; it grants no action authority. */
    synchronized boolean personalNotesReconciliationIdle(LocalTaskController expected){
        return live==this&&ownedController==expected&&(expected==null||!expected.isRunning())
                &&activeObservation==null&&activeNativeSearchObservation==null&&!capturePending&&!observationReadWorkPending()&&!actionWorkPending()&&!nativeCancellationWorkPending()
                &&(taskBackground==null||taskBackground.personalNotesRecoveryEligible())
                &&(taskWeb==null||taskWeb.released())
                &&(lease==null||(expected!=null&&lease.equals(expected.currentTaskId())));
    }
    synchronized void acceptBackgroundReconciliation(BackgroundSession.Cleanup cleanup)throws Exception{
        if(cleanup==null)throw new IllegalStateException("后台清理凭据缺失");
        if(cleanup.businessRecovery!=null){
            PublicProfileBusinessRecoveryClient.Receipt receipt=cleanup.businessRecovery;
            if(cleanup.prelaunchRecovery!=null||cleanup.postlaunchRecovery!=null||cleanup.publicProfileRecovery!=null||cleanup.personalNotesRecovery!=null
                    ||!cleanup.known||PublicProfileBusinessRecoveryClient.workPending()
                    ||!publicProfileBusinessReconciliationIdle(ownedController,receipt.request.taskId,receipt.request.ownerSha256)
                    ||!receipt.request.source().equals(cleanup.evidence.getString("reconciliation_source"))
                    ||!receipt.receiptSha256().equals(cleanup.evidence.getString("business_receipt_sha256")))
                throw new IllegalStateException("业务恢复的当前服务或凭据尚未确认");
            receipt.requirePersisted();receipt.requireOriginals(false);
            if(taskBackground!=null)taskBackground.acceptReconciliation(cleanup);return;
        }
        if(cleanup.personalNotesRecovery!=null){
            if(cleanup.prelaunchRecovery!=null||cleanup.postlaunchRecovery!=null||cleanup.publicProfileRecovery!=null
                    ||!personalNotesReconciliationIdle(ownedController))
                throw new IllegalStateException("备忘录恢复的控制器工作尚未排空");
            if(taskBackground!=null)taskBackground.acceptReconciliation(cleanup);return;
        }
        if(cleanup.publicProfileRecovery!=null){
            if(cleanup.prelaunchRecovery!=null||cleanup.postlaunchRecovery!=null||!publicProfileReconciliationIdle(ownedController))
                throw new IllegalStateException("公共恢复的控制器工作尚未排空");
            if(taskBackground!=null)taskBackground.acceptReconciliation(cleanup);return;
        }
        if(cleanup.postlaunchRecovery!=null){
            if(cleanup.prelaunchRecovery!=null||!postlaunchReconciliationIdle(ownedController))
                throw new IllegalStateException("已启动恢复的控制器工作尚未排空");
            if(taskBackground!=null)taskBackground.acceptReconciliation(cleanup);return;
        }
        if(cleanup.prelaunchRecovery==null){acceptBackgroundReconciliation(cleanup.evidence);return;}
        if(!prelaunchReconciliationIdle(ownedController))throw new IllegalStateException("启动前恢复的控制器工作尚未排空");
        if(taskBackground!=null)taskBackground.acceptReconciliation(cleanup);
    }
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
        requireHistoricalProfileWindow(background,observed);
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
    /** Read-only ownership check for an in-flight visual request. The old frame
     * is not relabeled fresh; the existing action path still reacquires and
     * compares current nodes before any tool effect.
     */
    /** Model admission for the explicit experiment shares the exact existing task,
     * controller and live background object; serialized policy data is insufficient. */
    void requireExperimentalModelScope(LocalTaskController expectedController,String id,TaskAuthorization.Gate auth,
            BackgroundSession expected,Cancellation cancel,long deadline){
        if(expected==null||!expected.usesExperimentalPublicOwnGroup())return;
        synchronized(this){
            TaskAuthorization.require(live==this&&ownedController==expectedController&&ownsAuthorization(id,auth)
                    &&taskBackground==expected&&id.equals(expected.taskId)
                    &&auth.authorization.instructionSha256.equals(expected.ownerSha256),"本地模型后台作用域已退休");
        }
        requireTaskAuthorization(id,auth);expected.requirePolicyBeforeEffect(cancel,deadline);
        synchronized(this){
            TaskAuthorization.require(live==this&&ownedController==expectedController&&ownsAuthorization(id,auth)
                    &&taskBackground==expected&&id.equals(expected.taskId),"本地模型策略读取期间任务已退休");
        }
        if(cancel==null||cancel.isCancelled()||SystemClock.elapsedRealtime()>=deadline)
            throw new IllegalStateException("本地模型原任务已停止或到期");
    }
    void requireNativeCalendarSourceOwnership(LocalTaskController controller,NativeAppSession nativeTask,
            BackgroundSession background,PhoneObservation observed,long taskDeadline){
        controller.requireNativeCalendarModelSource(nativeTask,background,taskDeadline);
        synchronized(this){
            calendarFreshRequire(live==this&&ownedController==controller&&taskWeb==null&&current==observed
                    &&currentGraph!=null&&currentBitmap!=null&&!currentBitmap.isRecycled()
                    &&ownsAuthorization(nativeTask.taskId,nativeTask.authorization)&&ownsBackground(nativeTask.taskId,background)
                    &&nativeTask.domain().frame.observationId.equals(observed.id)&&!actionWorkPending()
                    &&!observationReadWorkPending()&&!nativeCancellationWorkPending(),
                    "original calendar source must be the actual idle owned pixel publication");
        }
        requireTaskAuthorization(nativeTask.taskId,nativeTask.authorization);
        requireScopeObservation(nativeTask.taskId,observed);requireAuthorizationObservation(nativeTask.taskId,nativeTask.authorization,observed);
        requireBackgroundObservation(nativeTask.taskId,observed);
        controller.requireNativeCalendarModelSource(nativeTask,background,taskDeadline);
    }

    void requireVisualFrameOwnership(LocalTaskController expectedController,String id,
            TaskAuthorization.Gate auth,BackgroundSession expected,PhoneObservation observed,DecisionGrammar grammar){
        synchronized(this){
            TaskAuthorization.require(live==this&&ownedController==expectedController&&ownsAuthorization(id,auth)
                    &&expected!=null&&taskBackground==expected&&id.equals(expected.taskId),
                    "视觉请求的任务或后台空间已退休");
        }
        requireTaskAuthorization(id,auth);requireBackgroundObservation(id,observed);
        TaskAuthorization.require(grammar!=null&&grammar.authorization!=null
                &&grammar.authorization.authorization==auth.authorization&&id.equals(grammar.authorization.taskId)
                &&observed.id.equals(grammar.observationId)&&observed.packageName.equals(grammar.currentPackage)
                &&auth.authorization.instructionSha256.equals(expected.ownerSha256),
                "视觉请求与原始画面、工具语法或用户指令不一致");
        synchronized(this){
            TaskAuthorization.require(live==this&&ownedController==expectedController&&ownsAuthorization(id,auth)
                    &&taskBackground==expected&&!expected.released(),"视觉请求在校验期间已退休");
        }
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
        // A selected profile installation need not be installed in the controller's user.
        // This adds read-only discovery facts; launch and action still require the live lease.
        if(background!=null&&background.profileTarget()!=null){
            org.trillionnium.hepta.background.ProfileTarget target=background.profileTarget();
            available.put(target.packageName,target.appLabel()+" · 工作资料 "+target.profile.userId);
        }
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
        try{return new ObservationDiagnostics(request.taskId,request.requestId,
                background.ownerSha256,target.packageName,background.generation,request.displayId,++diagnosticRequests,request.started,request.deadline);}
        catch(RuntimeException unavailable){return null;}
    }
    /** Static: it cannot capture the Service, request, Graph, node or Bitmap. */
    private static final class DiagnosticSnapshot implements java.util.concurrent.Callable<String> {
        private final ObservationDiagnostics values;
        DiagnosticSnapshot(ObservationDiagnostics values){this.values=values;}
        @SuppressWarnings("unchecked") @Override public String call(){
            Map<String,Object> snapshot=values.snapshot(SystemClock.elapsedRealtime());
            String raw=new JSONObject(snapshot).toString();
            if(!fits(snapshot)&&snapshot.containsKey("last_native_sample_graph_change")){
                snapshot.remove("last_native_sample_graph_change");
                snapshot.put("native_sample_graph_detail_omitted_for_budget",true);
                raw=new JSONObject(snapshot).toString();
            }
            if(snapshot.containsKey("last_native_full_graph_change")){
                // Trim only this terminal snapshot copy. Keep stage/count/availability
                // even when long structural names exceed the existing JSON budget.
                if(!fits(snapshot)&&snapshot.containsKey("last_native_saved_graph_change")){
                    snapshot.remove("last_native_saved_graph_change");snapshot.put("native_saved_graph_detail_omitted_for_budget",true);
                }
                Map<String,Object> detail=new LinkedHashMap<String,Object>((Map<String,Object>)snapshot.get("last_native_full_graph_change"));
                snapshot.put("last_native_full_graph_change",detail);
                if(detail.get("node_differences") instanceof List){
                    List<Object> rows=new ArrayList<Object>((List<Object>)detail.get("node_differences"));detail.put("node_differences",rows);
                    while(!fits(snapshot)&&!rows.isEmpty()){
                        rows.remove(rows.size()-1);detail.put("retained_detail_count",rows.size());
                        detail.put("node_differences_truncated",true);detail.put("details_omitted_for_budget",true);
                    }
                }
                if(detail.get("compact_node_differences") instanceof List){
                    List<Object> rows=new ArrayList<Object>((List<Object>)detail.get("compact_node_differences"));
                    detail.put("compact_node_differences",rows);
                    int total=((Number)detail.get("changed_path_count")).intValue();
                    while(!fits(snapshot)&&!rows.isEmpty()){
                        rows.remove(rows.size()-1);detail.put("compact_retained_count",rows.size());
                        detail.put("compact_omitted_count",total-rows.size());detail.put("compact_truncated",true);
                        detail.put("compact_omitted_for_budget",true);
                    }
                }
                raw=new JSONObject(snapshot).toString();
            }
            if(snapshot.containsKey("last_native_saved_graph_change")){
                boolean omit=raw.getBytes(StandardCharsets.UTF_8).length>ObservationDiagnostics.MAX_JSON_BYTES;
                try{omit=omit||new JSONObject(snapshot).toString(2).getBytes(StandardCharsets.UTF_8).length>ObservationDiagnostics.MAX_JSON_BYTES;}
                catch(Exception unavailable){omit=true;}
                if(omit){
                    snapshot.remove("last_native_saved_graph_change");
                    snapshot.put("native_saved_graph_detail_omitted_for_budget",true);
                    raw=new JSONObject(snapshot).toString();
                }
            }
            if(raw.getBytes(StandardCharsets.UTF_8).length>ObservationDiagnostics.MAX_JSON_BYTES
                    ||snapshot.containsKey("last_native_full_graph_change")&&!fits(snapshot))
                throw new IllegalStateException("bounded observation diagnostic exceeded");
            return raw;
        }
        private static boolean fits(Map<String,Object> value){
            try{return new JSONObject(value).toString().getBytes(StandardCharsets.UTF_8).length<=ObservationDiagnostics.MAX_JSON_BYTES
                    &&new JSONObject(value).toString(2).getBytes(StandardCharsets.UTF_8).length<=ObservationDiagnostics.MAX_JSON_BYTES;}
            catch(Exception unavailable){return false;}
        }
    }
    /** Static pure values, with no Service, request, Graph, node or Bitmap reference. */
    private static final class PrivateCensusSnapshot implements java.util.concurrent.Callable<String> {
        private final ObservationDiagnostics values;
        PrivateCensusSnapshot(ObservationDiagnostics values){this.values=values;}
        @Override public String call()throws Exception{
            Map<String,Object> snapshot=values.privateCensusSnapshot(SystemClock.elapsedRealtime());
            JSONObject value=new JSONObject(snapshot);
            if(value.toString().getBytes(StandardCharsets.UTF_8).length>ObservationDiagnostics.MAX_PRIVATE_JSON_BYTES
                    ||value.toString(2).getBytes(StandardCharsets.UTF_8).length>ObservationDiagnostics.MAX_PRIVATE_JSON_BYTES){
                snapshot.remove("before");snapshot.remove("after");snapshot.put("complete_pair_recorded",false);
                snapshot.put("raw_pair_count",0);snapshot.put("node_text_recorded",false);
                snapshot.put("raw_pair_omitted_for_budget",true);snapshot.put("status","serialization_budget_exceeded");
                value=new JSONObject(snapshot);
            }
            String raw=value.toString();
            if(raw.getBytes(StandardCharsets.UTF_8).length>ObservationDiagnostics.MAX_PRIVATE_JSON_BYTES
                    ||value.toString(2).getBytes(StandardCharsets.UTF_8).length>ObservationDiagnostics.MAX_PRIVATE_JSON_BYTES)
                throw new IllegalStateException("bounded private census metadata exceeded");
            return raw;
        }
    }
    /** Each observation owns its samples/capture and the caller's original deadline. */
    private static final class NativeReadIdentity {
        final String packageName,generation,owner,window;
        final WindowOwnership profileWindow;
        final int displayId,windowId,rotation,left,top,right,bottom;
        NativeReadIdentity(Graph graph){
            packageName=graph.packageName;generation=graph.backgroundGeneration;owner=graph.backgroundOwnerSha;
            displayId=graph.displayId;windowId=graph.windowId;rotation=graph.rotation;
            left=graph.bounds.left;top=graph.bounds.top;right=graph.bounds.right;bottom=graph.bounds.bottom;
            window=windowIdentity(graph.windowMetadata);profileWindow=graph.profileWindow;
            if(window==null)throw new IllegalStateException("complete native window identity required");
        }
        private static String windowIdentity(Object value){
            return value instanceof ObservedWindowMetadata?((ObservedWindowMetadata)value).bindFreshness(""):null;
        }
        boolean matches(Graph graph){
            if(graph!=null)requireSameProfileOwner(profileWindow,graph.profileWindow);
            return graph!=null&&graph.nativeObservationComplete&&!graph.truncated
                    &&packageName.equals(graph.packageName)&&java.util.Objects.equals(generation,graph.backgroundGeneration)
                    &&java.util.Objects.equals(owner,graph.backgroundOwnerSha)&&displayId==graph.displayId&&windowId==graph.windowId
                    &&rotation==graph.rotation&&left==graph.bounds.left&&top==graph.bounds.top
                    &&right==graph.bounds.right&&bottom==graph.bounds.bottom&&window.equals(windowIdentity(graph.windowMetadata));
        }
    }
    /** Issued only after the failed request's actual serial read work has returned.
     * No Graph, node, Bitmap, callback, model text or deserializable authority is retained. */
    static final class NativeObservationRetryProof {
        private final Object issuer,authorization;
        private final PhoneObservation before;
        private final BackgroundSession background;
        private final NativeReadIdentity identity;
        private final String taskId,requestId;
        private final long started,deadline,failedAt,drainedAt;
        private final int completedReadWorks,graphChanges,captureFailures,sealedEventFailures;
        private final java.util.concurrent.atomic.AtomicBoolean consumed=new java.util.concurrent.atomic.AtomicBoolean();
        private NativeObservationRetryProof(Object issuer,Object authorization,PhoneObservation before,ObservationRequest request,long drainedAt){
            this.issuer=issuer;this.authorization=authorization;this.before=before;this.background=request.background;
            identity=request.readIdentity;taskId=request.taskId;requestId=request.requestId;started=request.started;
            deadline=request.deadline;failedAt=request.failedAt;this.drainedAt=drainedAt;completedReadWorks=request.readWorksFinished;
            graphChanges=request.readGraphChanges;captureFailures=request.readCaptureFailures;
            sealedEventFailures=request.readSealedEventFailures;
        }
        void requireOriginal(Object service,String task,Object authorization,PhoneObservation before){
            if(issuer!=service||!taskId.equals(task)||this.authorization!=authorization||this.before!=before||consumed.get())
                throw new IllegalStateException("页面已更新，本次重新观察已停止");
        }
        Map<String,Object> evidence(){
            Map<String,Object> value=new java.util.LinkedHashMap<String,Object>();
            value.put("schema","hepta.native-observation-retry-proof.v1");value.put("task_id",taskId);
            value.put("failed_request_id",requestId);value.put("before_observation_id",before.id);
            value.put("package",identity.packageName);value.put("window_id",identity.windowId);value.put("display_id",identity.displayId);
            value.put("owner_sha256",identity.owner);value.put("background_generation",identity.generation);
            if(identity.profileWindow!=null)value.put("actual_profile_window",identity.profileWindow.evidence());
            value.put("failed_request_started_elapsed_ms",started);value.put("failed_request_deadline_elapsed_ms",deadline);
            value.put("failed_request_terminal_elapsed_ms",failedAt);value.put("failed_request_terminal_status","failed");
            value.put("read_queue_drain_observed_elapsed_ms",drainedAt);value.put("completed_read_works",completedReadWorks);
            value.put("same_identity_graph_changes",graphChanges);value.put("capture_failures",captureFailures);
            value.put("sealed_capture_target_event_failures",sealedEventFailures);
            value.put("read_worker_drained",true);value.put("failed_request_resources_released",true);
            value.put("unknown_events",0);value.put("grants_action_authority",false);value.put("renews_failed_request",false);
            return java.util.Collections.unmodifiableMap(value);
        }
    }
    /** One initial read only: a drained failed request, never a published frame or effect permit.
     * Unlike stale-action recovery, this proof has no previous/current observation. */
    static final class InitialObservationRetryProof {
        private final Object issuer,controller,nativeTask,authorization;
        private final BackgroundSession background;
        private final NativeReadIdentity identity;
        private final String taskId,requestId;
        private final long taskDeadline,started,deadline,failedAt,drainedAt;
        private final int completedReadWorks;
        private final java.util.concurrent.atomic.AtomicBoolean consumed=new java.util.concurrent.atomic.AtomicBoolean();
        private InitialObservationRetryProof(Object issuer,ObservationRequest request,long drainedAt){
            this.issuer=issuer;controller=request.initialController;nativeTask=request.initialNativeTask;
            authorization=request.readAuthorization;background=request.background;identity=request.initialIdentity;
            taskId=request.taskId;requestId=request.requestId;taskDeadline=request.initialTaskDeadline;
            started=request.started;deadline=request.deadline;failedAt=request.failedAt;this.drainedAt=drainedAt;
            completedReadWorks=request.readWorksFinished;
        }
        void requireOriginal(Object service,Object controller,Object nativeTask,String task,Object authorization,
                             BackgroundSession background,long taskDeadline){
            if(issuer!=service||this.controller!=controller||this.nativeTask!=nativeTask||!taskId.equals(task)
                    ||this.authorization!=authorization||this.background!=background||this.taskDeadline!=taskDeadline||consumed.get())
                throw new IllegalStateException("首次页面读取的任务身份已变化");
        }
        Map<String,Object> evidence(){
            Map<String,Object> value=new java.util.LinkedHashMap<String,Object>();
            value.put("schema","hepta.initial-native-observation-retry-proof.v1");value.put("task_id",taskId);
            value.put("failed_request_id",requestId);value.put("package",identity.packageName);
            value.put("window_id",identity.windowId);value.put("display_id",identity.displayId);
            value.put("owner_sha256",identity.owner);value.put("background_generation",identity.generation);
            if(identity.profileWindow!=null)value.put("actual_profile_window",identity.profileWindow.evidence());
            value.put("original_task_deadline_elapsed_ms",taskDeadline);
            value.put("failed_request_started_elapsed_ms",started);value.put("failed_request_deadline_elapsed_ms",deadline);
            value.put("failed_request_terminal_elapsed_ms",failedAt);value.put("failed_request_terminal_status","failed");
            value.put("read_queue_drain_observed_elapsed_ms",drainedAt);value.put("completed_read_works",completedReadWorks);
            value.put("reason","sealed_pair_target_event_after_window_check_at_settle_limit");
            value.put("actual_task_read_ordinal",1);value.put("read_worker_drained",true);
            value.put("failed_request_resources_released",true);value.put("unknown_events",0);
            value.put("previous_observation_required",false);value.put("grants_action_authority",false);
            value.put("renews_failed_request",false);value.put("business_completion_verified",false);
            return java.util.Collections.unmodifiableMap(value);
        }
    }
    /** A separate entered-action read proof. No published frame or action token
     * crosses the actual serial read-queue drain boundary. */
    static final class PostEffectObservationRetryProof {
        private final Object issuer,controller,authorization;
        private final NativeAppSession nativeTask;private final NativeAppSession.PostEffectReadPermit permit;
        private final BackgroundSession background;private final NativeReadIdentity identity;
        private final String taskId,requestId;
        private final long taskDeadline,transitionDeadline,started,deadline,failedAt,drainedAt;
        private final int readOrdinal,completedReadWorks;
        private final String reason;private final Object samplingHandoff;
        private final Map<String,Object> samplingEvidence;
        private final java.util.concurrent.atomic.AtomicBoolean consumed=new java.util.concurrent.atomic.AtomicBoolean();
        private PostEffectObservationRetryProof(Object issuer,ObservationRequest request,long drainedAt){
            this(issuer,request,drainedAt,request.postEffectIdentity,"sealed_pair_target_event_after_window_check",null,null);
        }
        private PostEffectObservationRetryProof(Object issuer,ObservationRequest request,long drainedAt,
                NativeReadIdentity identity,String reason,Object samplingHandoff,Map<String,Object> samplingEvidence){
            this.issuer=issuer;controller=request.postEffectController;nativeTask=request.postEffectNativeTask;
            this.reason=reason;this.samplingHandoff=samplingHandoff;
            this.samplingEvidence=samplingEvidence==null?null:java.util.Collections.unmodifiableMap(
                    new java.util.LinkedHashMap<String,Object>(samplingEvidence));
            permit=request.postEffectPermit;authorization=request.readAuthorization;background=request.background;
            this.identity=identity;taskId=request.taskId;requestId=request.requestId;
            taskDeadline=request.postEffectTaskDeadline;transitionDeadline=request.postEffectTransitionDeadline;
            started=request.started;deadline=request.deadline;failedAt=request.failedAt;this.drainedAt=drainedAt;
            readOrdinal=request.taskReadOrdinal;completedReadWorks=request.readWorksFinished;
        }
        void requireOriginal(Object service,Object controller,NativeAppSession nativeTask,NativeAppSession.PostEffectReadPermit permit,
                String task,Object authorization,BackgroundSession background,long taskDeadline){
            if(issuer!=service||this.controller!=controller||this.nativeTask!=nativeTask||this.permit!=permit
                    ||!taskId.equals(task)||this.authorization!=authorization||this.background!=background
                    ||this.taskDeadline!=taskDeadline||consumed.get())
                throw new IllegalStateException("操作后重新观察的私有任务身份已变化");
        }
        Map<String,Object> evidence(){
            Map<String,Object> value=new java.util.LinkedHashMap<String,Object>();
            value.put("schema","hepta.native-post-effect-observation-retry-proof.v1");value.put("task_id",taskId);
            value.put("failed_request_id",requestId);value.put("package",identity.packageName);
            value.put("window_id",identity.windowId);value.put("display_id",identity.displayId);
            value.put("owner_sha256",identity.owner);value.put("background_generation",identity.generation);
            if(identity.profileWindow!=null)value.put("actual_profile_window",identity.profileWindow.evidence());
            value.put("original_task_deadline_elapsed_ms",taskDeadline);
            value.put("original_transition_deadline_elapsed_ms",transitionDeadline);
            value.put("failed_request_started_elapsed_ms",started);value.put("failed_request_deadline_elapsed_ms",deadline);
            value.put("failed_request_terminal_elapsed_ms",failedAt);value.put("failed_request_terminal_status","failed");
            value.put("read_queue_drain_observed_elapsed_ms",drainedAt);value.put("completed_read_works",completedReadWorks);
            value.put("actual_task_read_ordinal",readOrdinal);value.put("reason",reason);
            if(samplingEvidence!=null)value.put("sampling_exhaustion",samplingEvidence);
            value.put("read_worker_drained",true);value.put("failed_request_resources_released",true);value.put("unknown_events",0);
            value.put("grants_action_authority",false);value.put("action_replayed",false);value.put("renews_failed_request",false);
            value.put("business_completion_verified",false);return java.util.Collections.unmodifiableMap(value);
        }
    }
    /** One private value-only handoff for a new read. No Graph, pixel or node
     * survives here, and this object cannot authorize a model or an effect. */
    private static final class PostEffectSamplingRetry {
        final Object issuer;final String taskId,requestId;final NativeReadIdentity identity;
        final ObservationStabilityGate.FrameKey key;
        final long started,deadline,taskDeadline,transitionDeadline,firstStarted,firstCompleted,firstSampled,
                lastStarted,lastCompleted,lastSampled;
        final int typedChildFailures;final boolean oldIdentityLatch;
        boolean invalidated,closed;
        private PostEffectSamplingRetry(Object issuer,ObservationRequest request,Graph graph,long now){
            this.issuer=issuer;taskId=request.taskId;requestId=request.requestId;
            identity=new NativeReadIdentity(graph);key=frameKey(graph);
            started=request.started;deadline=request.deadline;taskDeadline=request.postEffectTaskDeadline;
            transitionDeadline=request.postEffectTransitionDeadline;
            firstStarted=request.postEffectSamplingStarted;firstCompleted=request.postEffectSamplingCompleted;
            firstSampled=request.postEffectSamplingAt;lastStarted=graph.readStartedElapsedMs;
            lastCompleted=graph.readCompletedElapsedMs;lastSampled=now;
            typedChildFailures=request.postEffectSamplingTypedChildFailures;oldIdentityLatch=request.postEffectIdentityRejected;
        }
        Map<String,Object> evidence(){
            Map<String,Object> value=new java.util.LinkedHashMap<String,Object>();
            value.put("schema","hepta.native-post-effect-sampling-exhaustion.v1");
            value.put("typed_read_failure","background_child_unavailable");value.put("typed_child_failure_count",typedChildFailures);
            value.put("first_read_started_elapsed_ms",firstStarted);value.put("first_read_completed_elapsed_ms",firstCompleted);
            value.put("first_sampled_elapsed_ms",firstSampled);value.put("last_read_started_elapsed_ms",lastStarted);
            value.put("last_read_completed_elapsed_ms",lastCompleted);value.put("last_sampled_elapsed_ms",lastSampled);
            value.put("settle_limit_ms",ObservationStabilityGate.SETTLE_LIMIT_MS);
            value.put("complete_same_window_pair",true);value.put("failed_partial_graphs_discarded",true);
            value.put("old_identity_latch_preserved",oldIdentityLatch);value.put("old_graph_or_pixels_reused",false);
            value.put("continuous_pixels_or_atomic_window_snapshot_claimed",false);
            value.put("grants_observation_or_action_authority",false);return value;
        }
    }
    private final Object postEffectSamplingLock=new Object();
    private PostEffectSamplingRetry pendingPostEffectSampling;
    private void discardPostEffectSampling(PostEffectSamplingRetry expected){
        if(expected==null)return;
        synchronized(postEffectSamplingLock){
            expected.invalidated=true;expected.closed=true;
            if(pendingPostEffectSampling==expected)pendingPostEffectSampling=null;
        }
    }
    private void discardPostEffectSamplingForTask(String task){
        synchronized(postEffectSamplingLock){
            PostEffectSamplingRetry pending=pendingPostEffectSampling;
            if(pending!=null&&pending.taskId.equals(task))discardPostEffectSampling(pending);
        }
    }
    private void notePostEffectSamplingEvent(int displayId){
        synchronized(postEffectSamplingLock){
            PostEffectSamplingRetry pending=pendingPostEffectSampling;
            // No typed-content exemption is borrowed for this narrow handoff.
            if(pending!=null&&(displayId<0||displayId==pending.identity.displayId))discardPostEffectSampling(pending);
        }
    }
    private boolean postEffectSamplingCurrent(PostEffectSamplingRetry pending,long now){
        synchronized(postEffectSamplingLock){
            return pending!=null&&pendingPostEffectSampling==pending&&pending.issuer==this
                    &&!pending.invalidated&&!pending.closed&&now>=pending.lastSampled
                    &&now<pending.deadline&&now<pending.taskDeadline&&now<pending.transitionDeadline;
        }
    }
    private boolean registerPostEffectSampling(final PostEffectSamplingRetry pending){
        long now=SystemClock.elapsedRealtime();
        synchronized(postEffectSamplingLock){
            if(pending==null||pending.issuer!=this||pendingPostEffectSampling!=null||pending.invalidated||pending.closed
                    ||now<pending.lastSampled||now>=pending.deadline||now>=pending.taskDeadline||now>=pending.transitionDeadline)return false;
            pendingPostEffectSampling=pending;
        }
        try{
            if(main.postDelayed(new Runnable(){public void run(){discardPostEffectSampling(pending);}},
                    Math.max(1,pending.deadline-now)))return true;
        }catch(RuntimeException unavailable){/* No expiry delivery means no new read eligibility. */}
        discardPostEffectSampling(pending);return false;
    }
    private PostEffectSamplingRetry postEffectSamplingHandoff(PostEffectObservationRetryProof proof){
        if(proof==null||proof.samplingHandoff==null)return null;
        if(!(proof.samplingHandoff instanceof PostEffectSamplingRetry))throw new IllegalStateException("unknown post-effect read handoff");
        PostEffectSamplingRetry pending=(PostEffectSamplingRetry)proof.samplingHandoff;
        if(proof.issuer!=this||pending.issuer!=this||proof.identity!=pending.identity
                ||!proof.taskId.equals(pending.taskId)||!proof.requestId.equals(pending.requestId)
                ||proof.deadline!=pending.deadline||proof.transitionDeadline!=pending.transitionDeadline)
            throw new IllegalStateException("post-effect sampling handoff identity changed");
        return pending;
    }
    private void discardPostEffectSamplingSubmission(PostEffectObservationRetryProof proof){
        if(proof!=null&&proof.samplingHandoff instanceof PostEffectSamplingRetry){
            PostEffectSamplingRetry pending=(PostEffectSamplingRetry)proof.samplingHandoff;
            if(pending.issuer==this)discardPostEffectSampling(pending);
        }
    }
    private void activateObservationRequest(ObservationRequest request){
        PostEffectSamplingRetry pending=postEffectSamplingHandoff(request.postEffectRetrySubmission);
        if(pending==null){activeObservation=request;return;}
        synchronized(postEffectSamplingLock){
            long now=SystemClock.elapsedRealtime();
            if(!postEffectSamplingCurrent(pending,now)||!request.postEffectRetrySubmission.consumed.get()
                    ||request.cancel.isCancelled()||now<request.started||now>=request.deadline)
                throw new IllegalStateException("post-effect sampling handoff expired or received an event");
            // Event delivery takes this same lock before reading activeObservation.
            activeObservation=request;pending.closed=true;pendingPostEffectSampling=null;
        }
    }

    /** Metadata of one complete failed-capture read; never a Graph, image or effect permit. */
    private static final class NativeResampleSeed {
        final String taskId,requestId;final BackgroundSession background;final Object authorization;
        final ObservationStabilityGate.FrameKey key;final NativeReadIdentity identity;
        final FrozenObservationWindow window;final long graphStartedAt,graphCompletedAt,events,unknownEvents;
        NativeResampleSeed(ObservationRequest request,Graph graph,FrozenObservationWindow window,long events,long unknown){
            taskId=request.taskId;requestId=request.requestId;background=request.background;authorization=request.readAuthorization;
            key=frameKey(graph);identity=new NativeReadIdentity(graph);this.window=window;
            graphStartedAt=graph.readStartedElapsedMs;graphCompletedAt=graph.readCompletedElapsedMs;
            this.events=events;unknownEvents=unknown;
        }
        boolean belongsTo(ObservationRequest request){
            return taskId.equals(request.taskId)&&requestId.equals(request.requestId)&&background==request.background
                    &&authorization!=null&&authorization==request.readAuthorization;
        }
    }
    /** Atomic event values only. Content coverage never grants an effect or extends a deadline. */
    private static final class ObservationEventWatermark {
        final long events,unknownEvents,contentEvents,boundaryEvents;
        ObservationEventWatermark(long events,long unknown,long content,long boundary){
            this.events=events;unknownEvents=unknown;contentEvents=content;boundaryEvents=boundary;
        }
        boolean sameBoundary(ObservationEventWatermark before){
            return before!=null&&unknownEvents==before.unknownEvents
                    &&boundaryEvents==before.boundaryEvents&&events>=before.events;
        }
        boolean onlyContentSince(ObservationEventWatermark before){
            return sameBoundary(before)&&unknownEvents==0&&before.unknownEvents==0&&contentEvents>=before.contentEvents
                    &&events-before.events==contentEvents-before.contentEvents;
        }
    }
    private static final class ObservationRequest {
        final String taskId;final File directory;final ObservationCallback callback;final Cancellation cancel;
        final ObservationStabilityGate gate;final long started,deadline;final BackgroundSession background;final int displayId;
        final String requestId=UUID.randomUUID().toString().replace("-","");
        PhoneObservation readBefore;Object readAuthorization;NativeReadIdentity readIdentity;
        Object nativeAxMode; // Immutable private mode copied only by the actual controller admission.
        NativeObservationRetryProof retrySubmission;
        Object initialController,initialNativeTask;long initialTaskDeadline;int taskReadOrdinal;
        InitialObservationRetryProof initialRetrySubmission;
        NativeReadIdentity initialIdentity;boolean initialIdentityRejected;
        WindowOwnership initialProfileOwner;boolean initialProfileBound;
        Object postEffectController;NativeAppSession postEffectNativeTask;NativeAppSession.PostEffectReadPermit postEffectPermit;
        long postEffectTaskDeadline,postEffectTransitionDeadline;PostEffectObservationRetryProof postEffectRetrySubmission;
        NativeReadIdentity postEffectIdentity;boolean postEffectIdentityRejected;
        boolean postEffectSamplingRejected;int postEffectSamplingTypedChildFailures;
        NativeReadIdentity postEffectSamplingIdentity;ObservationStabilityGate.FrameKey postEffectSamplingKey;
        long postEffectSamplingStarted,postEffectSamplingCompleted,postEffectSamplingAt;
        void rejectPostEffectIdentity(){postEffectIdentityRejected=true;postEffectSamplingRejected=true;}
        void resetPostEffectSampling(){postEffectSamplingIdentity=null;postEffectSamplingKey=null;}
        WindowOwnership postEffectProfileOwner;boolean postEffectProfileBound;
        NativeResampleSeed resampleSeed; // Main-owned first-sample lineage only.
        boolean readRecoveryRejected;String lastReadDigest;long failedAt=-1;
        int readWorksStarted,readWorksFinished,readGraphChanges,readCaptureFailures,readSealedEventFailures;
        boolean postEffectPublicationRecheckAttempted;
        boolean nativeAxPublicationRecheckAttempted;
        Graph captured;long token;int intervalRetries;boolean shotPending,nativeSample;
        ObservationDiagnostics trace;
        volatile boolean finished;
        volatile long events,unknownEvents;
        private long contentEvents,boundaryEvents;
        synchronized ObservationEventWatermark eventWatermark(){
            return new ObservationEventWatermark(events,unknownEvents,contentEvents,boundaryEvents);
        }
        synchronized void recordEvent(boolean unknown,int kind){
            if(finished)return;
            if(unknown)unknownEvents++;events++;
            if(kind==1){contentEvents++;note(ObservationDiagnostics.Event.EVENT_TARGET_CONTENT);}
            else if(kind==2){boundaryEvents++;note(ObservationDiagnostics.Event.EVENT_TARGET_BOUNDARY);}
            note(unknown?ObservationDiagnostics.Event.EVENT_UNKNOWN:ObservationDiagnostics.Event.EVENT_TARGET);
        }
        private String phase="queued";private long phaseAt;
        ObservationRequest(String taskId,File directory,ObservationCallback callback,Cancellation cancel,long deadline,BackgroundSession background){
            this.taskId=taskId;this.directory=directory;this.callback=callback;this.cancel=cancel;this.background=background;
            this.started=SystemClock.elapsedRealtime();this.deadline=deadline;this.phaseAt=started;
            this.displayId=background==null?Display.DEFAULT_DISPLAY:background.displayId();
            this.gate=new ObservationStabilityGate(started,deadline);
        }
        synchronized void phase(String value){if(!finished){phase=value;phaseAt=SystemClock.elapsedRealtime();if(trace!=null)trace.phase(value,phaseAt);}}
        synchronized void note(ObservationDiagnostics.Event event){note(event,false);}
        synchronized void note(ObservationDiagnostics.Event event,boolean typedChildUnavailable){
            if(postEffectController!=null){
                if(event==ObservationDiagnostics.Event.SAMPLE_STALE_ROOT||event==ObservationDiagnostics.Event.SCREENSHOT_GRAPH_STALE){
                    if(typedChildUnavailable)postEffectSamplingTypedChildFailures++;
                    else postEffectSamplingRejected=true;
                }
                if(event==ObservationDiagnostics.Event.SAMPLE_NO_ROOT||event==ObservationDiagnostics.Event.SCREENSHOT_GRAPH_MISSING
                        ||event==ObservationDiagnostics.Event.SAVED_GRAPH_MISSING||event==ObservationDiagnostics.Event.SAVED_GRAPH_STALE
                        ||event==ObservationDiagnostics.Event.AX_GRAPH_MISSING||event==ObservationDiagnostics.Event.AX_GRAPH_STALE)
                    postEffectSamplingRejected=true;
            }
            if(event==ObservationDiagnostics.Event.AX_GRAPH_MISSING||event==ObservationDiagnostics.Event.AX_GRAPH_STALE){
                readRecoveryRejected=true;
                if(initialController!=null)initialIdentityRejected=true;
                if(postEffectController!=null)rejectPostEffectIdentity();
            }
            if(event==ObservationDiagnostics.Event.AX_GRAPH_CHANGED)readCaptureFailures++;
            if(event==ObservationDiagnostics.Event.SAMPLE_NO_ROOT||event==ObservationDiagnostics.Event.SCREENSHOT_GRAPH_MISSING
                    ||event==ObservationDiagnostics.Event.SAVED_GRAPH_MISSING)readRecoveryRejected=true;
            if(event==ObservationDiagnostics.Event.SCREENSHOT_GRAPH_STALE||event==ObservationDiagnostics.Event.SCREENSHOT_GRAPH_CHANGED
                    ||event==ObservationDiagnostics.Event.SAVED_GRAPH_STALE||event==ObservationDiagnostics.Event.SAVED_GRAPH_CHANGED)readCaptureFailures++;
            // Missing startup samples establish no identity. A missing/stale paired
            // or post-persistence read cannot later qualify initial recovery.
            if(initialController!=null&&(event==ObservationDiagnostics.Event.SCREENSHOT_GRAPH_MISSING
                    ||event==ObservationDiagnostics.Event.SCREENSHOT_GRAPH_STALE
                    ||event==ObservationDiagnostics.Event.SAVED_GRAPH_MISSING||event==ObservationDiagnostics.Event.SAVED_GRAPH_STALE))
                initialIdentityRejected=true;
            if(postEffectController!=null&&(event==ObservationDiagnostics.Event.SCREENSHOT_GRAPH_MISSING
                    ||event==ObservationDiagnostics.Event.SCREENSHOT_GRAPH_STALE
                    ||event==ObservationDiagnostics.Event.SAVED_GRAPH_MISSING||event==ObservationDiagnostics.Event.SAVED_GRAPH_STALE))
                postEffectIdentityRejected=true;
            if(trace!=null)trace.note(event);
        }
        synchronized void worker(boolean active){
            if(active)readWorksStarted++;else readWorksFinished++;
            if(trace!=null)trace.worker(active);
        }
        synchronized void graph(String stage,Graph graph){
            if(postEffectController!=null&&graph!=null){
                // Preserve this fact before an event reset may close/null the graph.
                // Only the new sampling-successor eligibility is affected.
                if(!graph.nativeObservationComplete||graph.truncated)postEffectSamplingRejected=true;
                // A normal navigation can replace the app window. Only recovery
                // eligibility is latched until the latest sealed pair is chosen.
                if(background==null||displayId!=graph.displayId
                        ||!background.generation.equals(graph.backgroundGeneration)
                        ||!background.ownerSha256.equals(graph.backgroundOwnerSha)
                        ||!background.selection.initialPackage.equals(graph.packageName))rejectPostEffectIdentity();
                try{
                    NativeAppEvidence.requireProfileTarget(background==null?null:background.profileTarget(),graph.profileWindow);
                    if(postEffectProfileBound)requireSameProfileOwner(postEffectProfileOwner,graph.profileWindow);
                    else if(graph.nativeObservationComplete){postEffectProfileOwner=graph.profileWindow;postEffectProfileBound=true;}
                }catch(RuntimeException foreign){rejectPostEffectIdentity();}
                if(postEffectRetrySubmission!=null&&postEffectIdentity!=null&&!postEffectIdentity.matches(graph))rejectPostEffectIdentity();
            }
            if(initialController!=null&&graph!=null){
                // Recovery-only latch. Normal first-read window/geometry changes,
                // incomplete samples and startup gaps keep the original settle path.
                if(background==null||displayId!=graph.displayId
                        ||!background.generation.equals(graph.backgroundGeneration)
                        ||!background.ownerSha256.equals(graph.backgroundOwnerSha)
                        ||!background.selection.initialPackage.equals(graph.packageName))initialIdentityRejected=true;
                try{
                    NativeAppEvidence.requireProfileTarget(background==null?null:background.profileTarget(),graph.profileWindow);
                    if(initialProfileBound)requireSameProfileOwner(initialProfileOwner,graph.profileWindow);
                    else if(graph.nativeObservationComplete){initialProfileOwner=graph.profileWindow;initialProfileBound=true;}
                }catch(RuntimeException foreign){initialIdentityRejected=true;}
                if(initialRetrySubmission!=null&&initialIdentity!=null&&!initialIdentity.matches(graph))initialIdentityRejected=true;
            }
            if(readIdentity!=null&&graph!=null){
                if(!readIdentity.matches(graph))readRecoveryRejected=true;
                else{if(lastReadDigest!=null&&!lastReadDigest.equals(graph.digest))readGraphChanges++;lastReadDigest=graph.digest;}
            }
            if(trace==null||graph==null||graph.diagnosticStamp==null)return;
            ObservationDiagnostics.GraphStamp stamp=graph.diagnosticStamp;
            if(!trace.packageName.equals(stamp.packageName)||!trace.generation.equals(stamp.generation)
                    ||trace.displayId!=stamp.displayId||!trace.ownerSha.equals(stamp.ownerSha))return;
            String key=sha((graph.packageName+"|"+graph.windowId+"|"+graph.rotation+"|"+graph.bounds+"|"+graph.digest+"|"+graph.truncated).getBytes(StandardCharsets.UTF_8));
            long recordedAt=SystemClock.elapsedRealtime();
            if("sample_graph".equals(stage))trace.sampleGraphChange(stamp,recordedAt);
            trace.graph(stage,key,stamp.appTree,stamp.state,stamp.window,graph.truncated,recordedAt);
        }
        synchronized String diagnostic(String reason){
            long now=SystemClock.elapsedRealtime();
            return reason+" [phase="+phase+",elapsed_ms="+Math.max(0,now-started)+",phase_ms="+Math.max(0,now-phaseAt)+"]";
        }
    }
    /** Worker input contains only copied values, never a borrowed node/graph/Rect. */
    private static final class CaptureIdentity {
        final ObservationStabilityGate.FrameKey frame;final int displayId;final String generation;
        final long capturedAt,events,unknownEvents,graphStartedAt,graphCompletedAt;final boolean nativeRecheck;
        final FrozenObservationWindow frozenWindow;
        final WindowOwnership profileWindow;
        final ObservationDiagnostics.GraphStamp diagnosticStamp;
        final ObservationEventWatermark eventWatermark;
        CaptureIdentity(Graph graph,long capturedAt,long events,long unknownEvents,boolean nativeRecheck){
            this(graph,capturedAt,new ObservationEventWatermark(events,unknownEvents,0,0),nativeRecheck);
        }
        CaptureIdentity(Graph graph,long capturedAt,ObservationEventWatermark watermark,boolean nativeRecheck){
            eventWatermark=watermark;long events=watermark.events,unknownEvents=watermark.unknownEvents;
            frame=frameKey(graph);displayId=graph.displayId;generation=graph.backgroundGeneration;profileWindow=graph.profileWindow;
            this.capturedAt=capturedAt;this.events=events;this.unknownEvents=unknownEvents;this.nativeRecheck=nativeRecheck;
            graphStartedAt=graph.readStartedElapsedMs;graphCompletedAt=graph.readCompletedElapsedMs;
            frozenWindow=nativeRecheck?frozenObservationWindow(graph):null;diagnosticStamp=graph.diagnosticStamp;
        }
        boolean matches(Graph graph){requireSameProfileOwner(profileWindow,graph.profileWindow);
            return displayId==graph.displayId&&java.util.Objects.equals(generation,graph.backgroundGeneration)&&frame.equals(frameKey(graph));}
    }
    /** Copied window identity/geometry only. No node content, children or traversal digest is a field. */
    private static final class FrozenObservationWindow {
        final String packageName,metadata;
        final int windowId,displayId,rotation,left,top,right,bottom,width,height;
        final Map<String,Object> windows;
        final WindowOwnership profileWindow;
        FrozenObservationWindow(String pkg,int window,int display,int rotation,int left,int top,int right,int bottom,
                int width,int height,String metadata,Map<String,Object> windows,WindowOwnership profileWindow){
            this.profileWindow=profileWindow;packageName=pkg;windowId=window;displayId=display;this.rotation=rotation;
            this.left=left;this.top=top;this.right=right;this.bottom=bottom;this.width=width;this.height=height;
            this.metadata=metadata;this.windows=java.util.Collections.unmodifiableMap(new java.util.TreeMap<String,Object>(windows));
        }
        boolean matches(FrozenObservationWindow other){
            if(other!=null)requireSameProfileOwner(profileWindow,other.profileWindow);
            return other!=null&&packageName.equals(other.packageName)&&windowId==other.windowId&&displayId==other.displayId
                    &&rotation==other.rotation&&left==other.left&&top==other.top&&right==other.right&&bottom==other.bottom
                    &&width==other.width&&height==other.height&&metadata.equals(other.metadata)&&windows.equals(other.windows);
        }
    }
    /** Private lineage of a completed pre-encoding pair, never a freshness or effect permit. */
    private static final class ObservationPairSeal {
        final CaptureIdentity identity;final Object authorization;
        final long graphStartedAt,graphCompletedAt,sealedAt,events,unknownEvents;
        private ObservationPairSeal(CaptureIdentity identity,Object authorization,long start,long complete,long sealed,long events,long unknown){
            this.identity=identity;this.authorization=authorization;graphStartedAt=start;graphCompletedAt=complete;
            sealedAt=sealed;this.events=events;unknownEvents=unknown;
        }
    }
    private static final class ObservationAbandoned extends IllegalStateException {
        private static final long serialVersionUID=1L;
        ObservationAbandoned(){super("observation work retired or deadline reached");}
    }
    /** Exactly one owner at a time: worker -> posted main callback -> current snapshot. */
    private static final class ObservationProduct {
        Bitmap bitmap;File path;String id,digest;boolean published,nativeGraphRechecked,frozenWindowRechecked,wholeGraphRechecked;long checkedEvents=-1;
        final long events,unknownEvents,capturedAt,callbackAt;final CaptureIdentity identity;
        long pairStartedAt=-1,pairCompletedAt=-1,pairEvents=-1,encodeStartedAt=-1,encodeCompletedAt=-1,persistedAt=-1;
        long publicationCheckStartedAt=-1,publicationCheckCompletedAt=-1;
        long firstPublicationCheckStartedAt=-1,firstPublicationCheckCompletedAt=-1,firstPublicationCheckEvents=-1;
        int postEffectPublicationRechecks;
        ObservationPairSeal seal;NativeResampleSeed seed;
        Map<String,Object> formPair,postEncodingFormPair; // Complete read-only comparisons; never whole-tree equality.
        long formPairCompletedEvents=-1; // Frozen immediately after the complete census, before comparison.
        boolean contentPairSealed,postEncodingCompleteNativeRechecked;
        ObservationEventWatermark pairCompletedWatermark,postEncodingStartWatermark,postEncodingCompletedWatermark;
        ObservationProduct(CaptureIdentity identity,long callbackAt){
            this.identity=identity;this.callbackAt=callbackAt;events=identity.events;unknownEvents=identity.unknownEvents;capturedAt=identity.capturedAt;
        }
        Map<String,Object> captureEvidence(long publishedAt){
            Map<String,Object> e=new java.util.LinkedHashMap<String,Object>();
            e.put("schema","hepta.observation-capture.v1");e.put("mode",postEncodingFormPair!=null?"post_encoding_form_pair_history":formPair!=null?"pre_encoding_form_pair_history":seal==null?"post_encoding_whole_graph":"pre_encoding_paired_history");
            e.put("sample_graph_started_elapsed_ms",identity.graphStartedAt);e.put("sample_graph_completed_elapsed_ms",identity.graphCompletedAt);
            e.put("capture_requested_elapsed_ms",capturedAt);e.put("screenshot_callback_elapsed_ms",callbackAt);
            e.put("pair_graph_started_elapsed_ms",pairStartedAt);e.put("pair_graph_completed_elapsed_ms",pairCompletedAt);
            e.put("pair_sealed_elapsed_ms",seal==null?null:Long.valueOf(seal.sealedAt));
            e.put("png_encode_started_elapsed_ms",encodeStartedAt);e.put("png_encode_completed_elapsed_ms",encodeCompletedAt);
            e.put("png_persisted_and_hashed_elapsed_ms",persistedAt);
            e.put("post_persistence_check",postEncodingFormPair!=null?"complete_classified_native_form_and_window_census":postEncodingCompleteNativeRechecked?"complete_native_graph_and_window_census":
                    seal==null?"whole_observed_graph":"window_identity_geometry_permissions_and_reported_windows");
            e.put("publication_check_started_elapsed_ms",publicationCheckStartedAt);
            e.put("publication_check_completed_elapsed_ms",publicationCheckCompletedAt);e.put("published_elapsed_ms",publishedAt);
            e.put("capture_age_at_publication_ms",publishedAt-capturedAt);
            e.put("post_effect_window_recheck_count",postEffectPublicationRechecks);
            if(postEffectPublicationRechecks!=0){
                e.put("first_publication_check_started_elapsed_ms",firstPublicationCheckStartedAt);
                e.put("first_publication_check_completed_elapsed_ms",firstPublicationCheckCompletedAt);
                e.put("first_publication_check_event_watermark",firstPublicationCheckEvents);
                e.put("historical_pair_after_known_target_event",true);
            }
            if(formPair!=null){
                e.put("form_pair_comparison",formPair);
                e.put("form_pair_target_events_at_read_start",pairEvents);
                e.put("form_pair_target_events_at_census_completion",formPairCompletedEvents);
                e.put("form_pair_events_after_census_completion_admitted",false);
            }
            if(postEncodingFormPair!=null){
                e.put("post_encoding_form_pair_comparison",postEncodingFormPair);
                e.put("form_pair_events_after_census_completion_admitted",false);
            }
            e.put("native_content_pair_sealed",contentPairSealed);
            e.put("post_encoding_complete_native_graph_rechecked",postEncodingCompleteNativeRechecked);
            e.put("post_encoding_complete_native_graph_started_event_watermark",postEncodingStartWatermark==null?null:Long.valueOf(postEncodingStartWatermark.events));
            e.put("post_encoding_complete_native_graph_completed_event_watermark",postEncodingCompletedWatermark==null?null:Long.valueOf(postEncodingCompletedWatermark.events));
            e.put("post_encoding_content_events_covered",postEncodingStartWatermark==null||postEncodingCompletedWatermark==null?null:
                    Long.valueOf(postEncodingCompletedWatermark.contentEvents-postEncodingStartWatermark.contentEvents));
            e.put("window_boundary_events_at_capture",identity.eventWatermark.boundaryEvents);
            e.put("completion_watermark_after_full_census_only",true);
            e.put("published_pair_is_current_tree_claimed",false);
            e.put("pair_graph_event_watermark",pairEvents);e.put("pair_sealed_event_watermark",seal==null?null:Long.valueOf(seal.events));
            e.put("unknown_events_at_capture",unknownEvents);e.put("publication_check_event_watermark",checkedEvents);
            e.put("post_encoding_whole_graph_rechecked",wholeGraphRechecked);
            e.put("same_instant_pixels_and_ax_claimed",false);e.put("publication_refreshes_capture_age",false);
            e.put("fresh_action_validation_required",true);e.put("grants_action_authority",false);e.put("business_completion_verified",false);
            return java.util.Collections.unmodifiableMap(e);
        }
        void close(){
            seed=null;
            if(bitmap!=null){bitmap.recycle();bitmap=null;}
            // Best effort removal of this request's unpublished evidence, not a claim of durable deletion.
            if(path!=null&&!published){path.delete();path=null;}
        }
    }
    /** Legacy untyped events retain their original gates; they cannot enter new content coverage. */
    private void noteObservationEvent(int displayId){
        notePostEffectSamplingEvent(displayId);
        noteNativeSearchEvent(displayId,-1,null,false,false);
        ObservationRequest request=activeObservation;
        if(request!=null&&!request.finished&&(displayId<0||displayId==request.displayId))
            request.recordEvent(displayId<0,0);
    }
    /** SDK event metadata only: no source-node traversal, model label or package whitelist.
     * A content event must belong to the complete native graph currently owned by this capture.
     * Window/focus/unknown/foreign-owner events remain boundaries even when later values match. */
    private void noteObservationEvent(int displayId,int windowId,String packageName,boolean contentType){
        notePostEffectSamplingEvent(displayId);
        noteNativeSearchEvent(displayId,windowId,packageName,contentType,true);
        ObservationRequest request=activeObservation;
        if(request==null||request.finished||(displayId>=0&&displayId!=request.displayId))return;
        Graph captured=request.captured;boolean content=false;
        try{
            content=displayId>=0&&contentType&&captured!=null&&windowId>=0
                    &&windowId==captured.windowId&&packageName!=null&&packageName.equals(captured.packageName)
                    &&nativeObservationRecheckAllowed(request,captured);
        }catch(RuntimeException unavailable){content=false;}
        request.recordEvent(displayId<0,content?1:2);
    }
    /** One typed read, using the existing observation request/PNG publication.
     * This callback never grants input and never changes the native Session domain. */
    interface CalendarFreshCallback {
        void onFresh(CalendarFreshObservation proof);void onError(String detail);
        default void onDiagnostic(java.util.concurrent.Callable<String> snapshot) {}
        default void onPrivateCensusDiagnostic(java.util.concurrent.Callable<String> snapshot) {}
    }
    void observeNativeCalendarFresh(final LocalTaskController controller,
            final NativeAppSession.CalendarFreshRead read,final File evidenceDirectory,
            final Cancellation cancel,final long originalObservationDeadline,final CalendarFreshCallback callback)throws Exception{
        calendarFreshRequire(controller!=null&&read!=null&&cancel!=null&&callback!=null,"actual calendar read/controller required");
        read.claimObservationProducer(this);
        try{
            read.requireOriginal(read.session,read.background);requireCalendarFreshOwner(controller,read,null);
            long now=SystemClock.elapsedRealtime();
            calendarFreshRequire(!cancel.isCancelled()&&originalObservationDeadline>now
                    &&originalObservationDeadline<=read.deadlineElapsed&&originalObservationDeadline<=read.taskDeadlineElapsed
                    &&originalObservationDeadline<=read.background.expiresElapsed,"unchanged original calendar observation deadline required");
            File directory=MobiMindPrivateFiles.directory(evidenceDirectory,false);
            File expected=new File(new File(getFilesDir(),"control-tasks"),read.session.taskId).getCanonicalFile();
            calendarFreshRequire(directory.equals(expected),"actual original calendar task directory required");
            Cancellation ownedCancel=new Cancellation(){public boolean isCancelled(){
                return cancel.isCancelled()||read.producerRetired(HeptaAccessibilityService.this);}};
            CalendarFreshObserver observer=new CalendarFreshObserver(controller,read,directory,ownedCancel,originalObservationDeadline,callback);
            observeRequest(read.session.taskId,directory,ownedCancel,originalObservationDeadline,observer,null);
        }catch(Exception refused){read.close();throw refused;}
    }
    private static void calendarFreshRequire(boolean ok,String detail){
        if(!ok)throw new IllegalStateException(detail);
    }
    private void requireCalendarFreshOwner(LocalTaskController controller,NativeAppSession.CalendarFreshRead read,
            PhoneObservation observed){
        read.requireProducerIdentity(this);
        long now=SystemClock.elapsedRealtime();
        read.requirePublicationOwner(read.session,read.background,now);
        controller.requireNativeCalendarFreshOwner(read);
        synchronized(this){
            calendarFreshRequire(live==this&&ownedController==controller&&ownsAuthorization(read.session.taskId,read.session.authorization)
                    &&ownsBackground(read.session.taskId,read.background)&&taskBackground==read.background&&taskWeb==null,
                    "calendar service/controller/task/background identity changed");
            if(observed!=null)calendarFreshRequire(current==observed&&currentGraph!=null&&currentBitmap!=null
                    &&!currentBitmap.isRecycled()&&currentGraph.windowId==observed.windowId
                    &&currentGraph.displayId==read.session.displayId&&currentGraph.packageName.equals(observed.packageName),
                    "actual fresh calendar publication is no longer the current retained snapshot");
        }
        requireTaskAuthorization(read.session.taskId,read.session.authorization);
        if(observed!=null){
            requireScopeObservation(read.session.taskId,observed);
            requireAuthorizationObservation(read.session.taskId,read.session.authorization,observed);
            requireBackgroundObservation(read.session.taskId,observed);
        }else read.background.requireActive();
        controller.requireNativeCalendarFreshOwner(read);
        read.requirePublicationOwner(read.session,read.background,SystemClock.elapsedRealtime());
        synchronized(this){calendarFreshRequire(live==this&&ownedController==controller&&taskBackground==read.background
                &&ownsAuthorization(read.session.taskId,read.session.authorization)
                &&(observed==null||current==observed),"calendar owner changed during final currentness checks");}
    }
    private final class CalendarFreshObserver implements ObservationCallback {
        final LocalTaskController controller;final NativeAppSession.CalendarFreshRead read;
        final File directory;final Cancellation cancel;final long deadline;final CalendarFreshCallback callback;
        private ObservationRequest request;private boolean delivered;
        CalendarFreshObserver(LocalTaskController controller,NativeAppSession.CalendarFreshRead read,File directory,
                Cancellation cancel,long deadline,CalendarFreshCallback callback){
            this.controller=controller;this.read=read;this.directory=directory;this.cancel=cancel;
            this.deadline=deadline;this.callback=callback;
        }
        void bind(ObservationRequest actual){
            calendarFreshRequire(request==null&&actual!=null&&actual.callback==this&&actual.cancel==cancel
                    &&actual.background==read.background&&actual.directory.equals(directory)&&actual.deadline==deadline
                    &&actual.taskId.equals(read.session.taskId)&&actual.started>=read.startedElapsed,
                    "one actual original observation request required");request=actual;
        }
        void requireAdmission(ObservationRequest actual){
            calendarFreshRequire(request==actual&&!delivered&&!cancel.isCancelled(),"calendar read submission was retired");
            requireCalendarFreshOwner(controller,read,null);
            calendarFreshRequire(activeObservation==null&&!capturePending&&!observationReadWorkPending()
                    &&!actionWorkPending()&&!nativeCancellationWorkPending()&&nativeSearchSession==null
                    &&activeNativeSearchObservation==null&&nativeSearchRetryPending==null&&nativeAxMode==null,
                    "calendar read requires the existing observation/action/cancel lanes idle and pixel mode");
        }
        @Override public void onDiagnostic(java.util.concurrent.Callable<String> snapshot){callback.onDiagnostic(snapshot);}
        @Override public void onPrivateCensusDiagnostic(java.util.concurrent.Callable<String> snapshot){callback.onPrivateCensusDiagnostic(snapshot);}
        @Override public void onError(String detail){if(!delivered){delivered=true;callback.onError(detail);}}
        @Override public void onObservation(PhoneObservation observed){
            if(delivered){read.close();return;}delivered=true;
            try{
                calendarFreshRequire(request!=null&&request.finished&&activeObservation!=request&&!cancel.isCancelled()
                        &&observed!=null&&observed.capture==null&&ObservationCaptureEvidence.PIXELS.equals(observed.captureKind)
                        &&observed.screenshot!=null&&observed.screenshotSha256!=null
                        &&observed.capturedElapsedMillis>=request.started&&observed.capturedElapsedMillis>=read.modelReceivedElapsed,
                        "only the actual completed new pixel publication can issue calendar provenance");
                requireCalendarFreshOwner(controller,read,observed);
                long deliveredAt=SystemClock.elapsedRealtime();
                calendarFreshRequire(deliveredAt>=observed.capturedElapsedMillis&&deliveredAt<deadline,
                        "calendar publication expired at private proof seal");
                CalendarFreshObservation proof=new CalendarFreshObservation(HeptaAccessibilityService.this,this,observed,deliveredAt);
                callback.onFresh(proof);
            }catch(Exception refused){read.close();callback.onError("calendar fresh publication refused: "+message(refused));}
        }
    }
    void registerNativeCalendarInputTracking(NativeAppSession.CalendarFreshRead read,CalendarFreshObservation proof){
        calendarFreshRequire(read!=null&&proof!=null&&proof.service==this&&proof.producer.read==read,
                "same private calendar publication/read required for event tracking");
        read.requireInputTrackingRegistration(this);
        synchronized(nativeSearchEventLock){
            calendarFreshRequire(nativeCalendarTracked==null,"another calendar publication still owns event tracking");
            nativeCalendarTracked=proof;
        }
    }
    void retireNativeCalendarInputTracking(NativeAppSession.CalendarFreshRead read){
        synchronized(nativeSearchEventLock){
            CalendarFreshObservation actual=nativeCalendarTracked;
            if(actual!=null&&actual.producer.read==read)nativeCalendarTracked=null;
        }
    }
    /** Private ctor is reached only from CalendarFreshObserver after actual
     * request completion/current Phone publication. No map or test constructor. */
    static final class CalendarFreshObservation {
        private final HeptaAccessibilityService service;
        private final CalendarFreshObserver producer;
        private final PhoneObservation observed;
        private final long deliveredElapsed;
        private boolean envelopeReadAttempted;
        private final SearchEvents inputEvents;
        private final NativeSearchPlanning.EventMark originalInputEvents;
        private File recordPath;private String recordSha;private long recordBytes;
        private CalendarFreshObservation(HeptaAccessibilityService service,CalendarFreshObserver producer,
                PhoneObservation observed,long delivered){
            this.service=service;this.producer=producer;this.observed=observed;deliveredElapsed=delivered;
            inputEvents=new SearchEvents(observed.windowMetadata.displayId.intValue(),observed.packageName);
            inputEvents.window=observed.windowId;originalInputEvents=inputEvents.mark();
            producer.read.registerInputTracking(service,this);
        }
        void requireActionIssuer(HeptaAccessibilityService actual,LocalTaskController controller,NativeAppSession.CalendarFreshRead read){
            calendarFreshRequire(actual==service&&controller==producer.controller&&read==producer.read,
                    "same actual calendar publication service/controller/read required");
            read.requireProducerIdentity(actual);
        }
        PhoneObservation observationForAction(HeptaAccessibilityService actual,LocalTaskController controller,NativeAppSession.CalendarFreshRead read){
            requireActionIssuer(actual,controller,read);return observed;
        }
        void requireActionCurrentPure(HeptaAccessibilityService actual,LocalTaskController controller,NativeAppSession.CalendarFreshRead read){
            requireActionIssuer(actual,controller,read);controller.requireNativeCalendarFreshOwner(read);
            read.requirePublicationOwner(read.session,read.background,SystemClock.elapsedRealtime());
            synchronized(service){
                calendarFreshRequire(live==service&&service.ownedController==controller&&service.current==observed
                        &&service.currentGraph!=null&&service.currentBitmap!=null&&!service.currentBitmap.isRecycled()
                        &&service.ownsAuthorization(read.session.taskId,read.session.authorization)
                        &&service.ownsBackground(read.session.taskId,read.background)&&service.taskWeb==null,
                        "calendar current service/task/frame changed before input");
            }
            synchronized(service.nativeSearchEventLock){
                calendarFreshRequire(service.nativeCalendarTracked==this&&sameSearchEvents(originalInputEvents,inputEvents.mark()),
                        "calendar event arrived after the fresh publication; no input allowed");
            }
        }
        void retireInputTracking(){synchronized(service.nativeSearchEventLock){
            if(service.nativeCalendarTracked==this)service.nativeCalendarTracked=null;
        }}
        void requireRecordedOriginal(NativeAppSession.CalendarFreshRead read)throws Exception{
            calendarFreshRequire(read==producer.read&&producer.request!=null&&producer.request.finished
                    &&producer.request.callback==producer&&recordPath!=null&&NativeAppEvidence.sha(recordSha),
                    "same historical completed calendar publication required");
            synchronized(producer.request){
                calendarFreshRequire(producer.request.readWorksStarted==producer.request.readWorksFinished,
                        "calendar original read counters are incomplete");
            }
            MobiMindPrivateFiles.Read value=MobiMindPrivateFiles.read(recordPath,2*1024*1024,true);
            calendarFreshRequire(value.bytes.length==recordBytes&&recordSha.equals(MobiMindContract.sha(value.bytes)),
                    "original calendar publication record changed");value.unchangedPath();
            MobiMindPrivateFiles.Read png=MobiMindPrivateFiles.read(observed.screenshot,8*1024*1024,true);
            calendarFreshRequire(observed.screenshotSha256.equals(MobiMindContract.sha(png.bytes)),
                    "original fresh calendar PNG changed");png.unchangedPath();
        }
        void requireBound(NativeAppSession.CalendarFreshRead read)throws Exception{
            calendarFreshRequire(read==producer.read&&producer.request!=null&&producer.request.finished
                    &&producer.request.callback==producer&&producer.request.background==read.background
                    &&deliveredElapsed>=observed.capturedElapsedMillis&&deliveredElapsed<producer.deadline,
                    "same completed private calendar observation producer required");
            synchronized(producer.request){
                calendarFreshRequire(producer.request.readWorksStarted==producer.request.readWorksFinished,
                        "calendar observation read work counters are not complete");
            }
            // The raw waiter's local abandoned flag becomes true even on success.
            // It was enforced through publication, and is deliberately not a
            // substitute for the real controller/task cancellation checks here.
            long now=SystemClock.elapsedRealtime();
            calendarFreshRequire(now>=deliveredElapsed&&now<read.deadlineElapsed&&now<read.taskDeadlineElapsed,
                    "calendar publication clock moved backwards or original budget expired");
            service.requireCalendarFreshOwner(producer.controller,read,observed);
            requireActionCurrentPure(service,producer.controller,read);
            if(recordPath!=null){
                MobiMindPrivateFiles.Read current=MobiMindPrivateFiles.read(recordPath,2*1024*1024,true);
                calendarFreshRequire(current.bytes.length==recordBytes&&recordSha.equals(MobiMindContract.sha(current.bytes)),
                        "original calendar observation record changed");current.unchangedPath();
                service.requireCalendarFreshOwner(producer.controller,read,observed);
            }
        }
        PhoneObservation observationFor(LocalTaskController controller,NativeAppSession.CalendarFreshRead read)throws Exception{
            calendarFreshRequire(controller==producer.controller,"original controller required");requireBound(read);return observed;
        }
        synchronized NativeCalendarDateEnvelope readEnvelope(final NativeAppSession.CalendarFreshRead read)throws Exception{
            if(envelopeReadAttempted){read.close();throw new IllegalStateException("calendar envelope read was already attempted");}
            envelopeReadAttempted=true;
            try{
                requireBound(read);read.requireOriginal(read.session,read.background);
                File directory=MobiMindPrivateFiles.directory(producer.directory,false);
                calendarFreshRequire(observed.screenshot.getParentFile().equals(directory)
                        &&observed.screenshot.getAbsoluteFile().equals(observed.screenshot.getCanonicalFile()),
                        "actual published private PNG path required");
                byte[] bytes=observed.toEvidenceJson().toString(2).getBytes(StandardCharsets.UTF_8);
                calendarFreshRequire(bytes.length>0&&bytes.length<=2*1024*1024,"complete bounded calendar observation record required");
                File path=new File(directory,"native-calendar-fresh-frame-"+observed.id+".json");
                MobiMindPrivateFiles.writeNew(path,bytes);
                MobiMindPrivateFiles.Read actual=MobiMindPrivateFiles.read(path,2*1024*1024,true);
                calendarFreshRequire(java.util.Arrays.equals(bytes,actual.bytes),"actual calendar observation record readback differs");
                actual.unchangedPath();recordPath=path;recordSha=MobiMindContract.sha(actual.bytes);recordBytes=actual.bytes.length;
                NotesCompletionEvidence.Frame completion=producer.controller.calendarFreshCompletionFrame(read,observed);
                NativeAppEvidence.Frame facts=NativeAppObservation.copy(read.session.taskId,read.session.authorization,
                        read.background,observed,completion,recordSha);
                LocalInference.CurrentFrame image=new LocalInference.CurrentFrame(observed.screenshot,read.session.taskId,
                        read.goal.ownerSha256,observed.id,observed.backgroundGeneration,observed.packageName,observed.screenshotSha256,
                        observed.width,observed.height,observed.windowMetadata.displayId.intValue(),observed.windowId,
                        observed.rotation,observed.capturedElapsedMillis,read.originalImage.taskOwnerEvidence(),
                        new LocalInference.Currentness(){public void requireCurrent()throws Exception{CalendarFreshObservation.this.requireBound(read);}});
                NativeCalendarDateEnvelope envelope=NativeCalendarDateEnvelope.capture(read.goal,facts,image,
                        read.background.profileTarget(),read.runtime,new NativeCalendarDateProtocol.Clock(){
                            public long elapsedRealtime(){return SystemClock.elapsedRealtime();}});
                actual.unchangedPath();requireBound(read);return envelope;
            }catch(Exception refused){read.close();throw refused;}
        }
        Map<String,Object> evidence(){
            Map<String,Object> e=NativeAppEvidence.map();e.put("schema","hepta.native-calendar-fresh-publication.v1");
            e.put("task_id",producer.read.session.taskId);e.put("observation_request_id",producer.request.requestId);
            e.put("observation_id",observed.id);e.put("captured_elapsed_ms",observed.capturedElapsedMillis);
            e.put("request_started_elapsed_ms",producer.request.started);e.put("request_deadline_elapsed_ms",producer.deadline);
            e.put("callback_delivered_elapsed_ms",deliveredElapsed);e.put("background_generation",observed.backgroundGeneration);
            e.put("display_id",producer.read.session.displayId);e.put("window_id",observed.windowId);e.put("rotation",observed.rotation);
            e.put("png_sha256",observed.screenshotSha256);e.put("observation_record_path",recordPath==null?null:recordPath.getPath());
            e.put("observation_record_bytes",recordPath==null?null:Long.valueOf(recordBytes));e.put("observation_record_sha256",recordSha);
            e.put("actual_private_observation_producer",true);e.put("post_publication_pixels_independently_reobserved",false);
            e.put("grants_dispatch",false);e.put("input_attempted",false);return NativeAppEvidence.immutableMap(e);
        }
    }

    public void observe(final String taskId,final File evidenceDirectory,final Cancellation cancel,
                        final long deadline,final ObservationCallback callback) {
        observeRequest(taskId,evidenceDirectory,cancel,deadline,callback,null);
    }
    void observeAfterTransientFailure(final String taskId,final File evidenceDirectory,final Cancellation cancel,
                        final long deadline,final ObservationCallback callback,final NativeObservationRetryProof proof){
        if(proof==null)throw new IllegalArgumentException("private failed-read proof required");
        observeRequest(taskId,evidenceDirectory,cancel,deadline,callback,proof);
    }
    private void observeRequest(final String taskId,final File evidenceDirectory,final Cancellation cancel,
                        final long deadline,final ObservationCallback callback,final NativeObservationRetryProof retryProof){
        observeRequest(taskId,evidenceDirectory,cancel,deadline,callback,retryProof,null,null,null,null,0,null);
    }
    void observeInitialNative(final Object controller,final Object nativeTask,final String taskId,
                        final Object authorization,final BackgroundSession background,final File evidenceDirectory,
                        final Cancellation cancel,final long deadline,final long taskDeadline,
                        final ObservationCallback callback,final InitialObservationRetryProof proof){
        if(controller==null||nativeTask==null||authorization==null||background==null)
            throw new IllegalArgumentException("current native controller and background required");
        observeRequest(taskId,evidenceDirectory,cancel,deadline,callback,null,
                controller,nativeTask,authorization,background,taskDeadline,proof);
    }
    private void observeRequest(final String taskId,final File evidenceDirectory,final Cancellation cancel,
                        final long deadline,final ObservationCallback callback,final NativeObservationRetryProof retryProof,
                        final Object initialController,final Object initialNativeTask,final Object initialAuthorization,
                        final BackgroundSession initialBackground,final long taskDeadline,final InitialObservationRetryProof initialProof){
        observeRequest(taskId,evidenceDirectory,cancel,deadline,callback,retryProof,initialController,initialNativeTask,
                initialAuthorization,initialBackground,taskDeadline,initialProof,null,null,null,null,null,0,null);
    }
    void observePostEffectNative(final Object controller,final NativeAppSession nativeTask,final NativeAppSession.PostEffectReadPermit permit,
                        final String taskId,final Object authorization,final BackgroundSession background,final File evidenceDirectory,
                        final Cancellation cancel,final long deadline,final long taskDeadline,
                        final ObservationCallback callback,final PostEffectObservationRetryProof proof){
        if(controller==null||nativeTask==null||permit==null||authorization==null||background==null)
            throw new IllegalArgumentException("private accepted navigation and native controller required");
        observeRequest(taskId,evidenceDirectory,cancel,deadline,callback,null,null,null,null,null,0,null,
                controller,nativeTask,permit,authorization,background,taskDeadline,proof);
    }
    private void observeRequest(final String taskId,final File evidenceDirectory,final Cancellation cancel,
                        final long deadline,final ObservationCallback callback,final NativeObservationRetryProof retryProof,
                        final Object initialController,final Object initialNativeTask,final Object initialAuthorization,
                        final BackgroundSession initialBackground,final long taskDeadline,final InitialObservationRetryProof initialProof,
                        final Object postController,final NativeAppSession postNativeTask,final NativeAppSession.PostEffectReadPermit postPermit,
                        final Object postAuthorization,final BackgroundSession postBackground,final long postTaskDeadline,
                        final PostEffectObservationRetryProof postProof){
        final ObservationRequest request=new ObservationRequest(taskId,evidenceDirectory,callback,cancel,deadline,backgroundFor(taskId));
        if(callback instanceof CalendarFreshObserver)((CalendarFreshObserver)callback).bind(request);
        request.retrySubmission=retryProof;
        request.initialController=initialController;request.initialNativeTask=initialNativeTask;
        request.initialTaskDeadline=taskDeadline;request.initialRetrySubmission=initialProof;
        request.postEffectController=postController;request.postEffectNativeTask=postNativeTask;request.postEffectPermit=postPermit;
        request.postEffectTaskDeadline=postTaskDeadline;request.postEffectRetrySubmission=postProof;
        request.trace=observationDiagnostic(request);
        if(request.trace!=null)try{callback.onDiagnostic(new DiagnosticSnapshot(request.trace));}
        catch(RuntimeException unavailable){/* Optional diagnostics grant no authority and do not replace the observation. */}
        if(request.trace!=null)try{callback.onPrivateCensusDiagnostic(new PrivateCensusSnapshot(request.trace));}
        catch(RuntimeException unavailable){/* Pure optional evidence cannot replace the observation. */}
        main.post(new Runnable(){public void run(){
            if(!nativeSearchAllowsLegacyObservation(taskId)){discardPostEffectSamplingSubmission(postProof);callback.onError("搜索规划材料不能作为普通可执行观察；需先核验新导航效果");return;}
            if(activeObservation!=null){
                ObservationRequest old=activeObservation;
                if(!owns(old.taskId)||old.cancel.isCancelled())failObservation(old,"任务已经停止");
                else {discardPostEffectSamplingSubmission(postProof);callback.onError("已有屏幕观察尚未结束");return;}
            }
            if(capturePending){discardPostEffectSamplingSubmission(postProof);callback.onError("已有截图尚未结束");return;}
            if(observationIoBusy.get()){discardPostEffectSamplingSubmission(postProof);callback.onError(request.diagnostic("先前屏幕读取尚未退出，不堆积新观察"));return;}
            try{
                if(callback instanceof CalendarFreshObserver)((CalendarFreshObserver)callback).requireAdmission(request);
                if(postController!=null)admitPostEffectObservation(request,postAuthorization,postBackground);
                else if(initialController!=null)admitInitialObservation(request,initialAuthorization,initialBackground);
                else{
                    if(retryProof!=null)consumeObservationRetry(request,retryProof);
                    request.readBefore=current;request.readAuthorization=taskAuthorization;
                    if(current!=null&&taskAuthorization!=null&&nativeObservationRecheckAllowed(request,currentGraph))
                        request.readIdentity=new NativeReadIdentity(currentGraph);
                }
                recordObservationAdmission(request);
                bindNativeAxObservationRequest(request);
                activateObservationRequest(request);
            }catch(RuntimeException invalid){
                discardPostEffectSamplingSubmission(postProof);
                callback.onError("页面状态已变化，本次重新观察已停止");return;
            }
            watchObservation(request);sampleObservation(request);
        }});
    }
    private synchronized void recordObservationAdmission(ObservationRequest request){
        if(owns(request.taskId))request.taskReadOrdinal=++taskObservationAdmissions;
    }
    private synchronized void admitInitialObservation(ObservationRequest request,Object authorization,BackgroundSession background){
        long now=SystemClock.elapsedRealtime();InitialObservationRetryProof proof=request.initialRetrySubmission;
        if(live!=this||ownedController!=request.initialController||request.initialNativeTask==null
                ||authorization==null||authorization!=taskAuthorization||background==null||background!=request.background
                ||!owns(request.taskId)||!ownsBackground(request.taskId,background)||taskWeb!=null
                ||request.cancel.isCancelled()||locked(background)||activeObservation!=null
                ||capturePending||observationIoBusy.get()||actionWorkPending()||nativeCancellationWorkPending()
                ||now<request.started||now>=request.deadline||request.deadline>request.initialTaskDeadline
                ||request.deadline>ObservationStabilityGate.requestDeadline(request.started,request.initialTaskDeadline)
                ||taskObservationAdmissions!=(proof==null?0:1))
            throw new IllegalStateException("initial native read admission changed");
        request.readAuthorization=authorization;
        if(proof!=null){
            proof.requireOriginal(this,request.initialController,request.initialNativeTask,request.taskId,
                    authorization,background,request.initialTaskDeadline);
            if(request.started<proof.drainedAt||!proof.consumed.compareAndSet(false,true))
                throw new IllegalStateException("initial read drain or one-use boundary changed");
            request.initialIdentity=proof.identity;
        }
        // Deliberately do not copy current/currentGraph: they may belong to an old task.
    }
    private synchronized boolean initialObservationOwner(ObservationRequest request){
        return live==this&&request.initialController!=null&&ownedController==request.initialController
                &&request.initialNativeTask!=null&&request.readAuthorization!=null&&request.readAuthorization==taskAuthorization
                &&request.background!=null&&owns(request.taskId)&&ownsBackground(request.taskId,request.background)&&taskWeb==null
                &&request.taskReadOrdinal==taskObservationAdmissions;
    }
    private synchronized void admitPostEffectObservation(ObservationRequest request,Object authorization,BackgroundSession background){
        long now=SystemClock.elapsedRealtime();PostEffectObservationRetryProof proof=request.postEffectRetrySubmission;
        if(live!=this||ownedController!=request.postEffectController||request.postEffectNativeTask==null||request.postEffectPermit==null
                ||request.initialController!=null||request.retrySubmission!=null||authorization==null||authorization!=taskAuthorization
                ||background==null||background!=request.background||!owns(request.taskId)||!ownsBackground(request.taskId,background)
                ||taskWeb!=null||request.cancel.isCancelled()||locked(background)||activeObservation!=null
                ||capturePending||observationIoBusy.get()||actionWorkPending()||nativeCancellationWorkPending()
                ||taskObservationAdmissions<1||now<request.started||now>=request.deadline
                ||request.deadline>request.postEffectTaskDeadline
                ||request.deadline>ObservationStabilityGate.requestDeadline(request.started,request.postEffectTaskDeadline))
            throw new IllegalStateException("post-effect native read admission changed");
        request.postEffectPermit.requireOwner(request.postEffectNativeTask,authorization,request.taskId,background.selection,background.generation,background.displayId());
        request.postEffectTransitionDeadline=request.postEffectPermit.transitionDeadline();
        if(request.deadline>request.postEffectTransitionDeadline||now>=request.postEffectTransitionDeadline)
            throw new IllegalStateException("original transition read budget expired");
        if(proof!=null){
            proof.requireOriginal(this,request.postEffectController,request.postEffectNativeTask,request.postEffectPermit,
                    request.taskId,authorization,background,request.postEffectTaskDeadline);
            if(taskObservationAdmissions!=proof.readOrdinal||request.started<proof.drainedAt
                    ||request.postEffectTransitionDeadline!=proof.transitionDeadline||!proof.consumed.compareAndSet(false,true))
                throw new IllegalStateException("post-effect read drain or one-use boundary changed");
            PostEffectSamplingRetry sampling=postEffectSamplingHandoff(proof);
            if(sampling!=null&&!postEffectSamplingCurrent(sampling,SystemClock.elapsedRealtime()))
                throw new IllegalStateException("post-effect sampling handoff retired before admission");
            request.postEffectIdentity=proof.identity;
        }
        request.postEffectPermit.admit(proof!=null);request.readAuthorization=authorization;
        // No current/currentGraph copy: the old home observation cannot anchor a new page.
    }
    private synchronized boolean postEffectObservationOwner(ObservationRequest request){
        if(live!=this||request.postEffectController==null||ownedController!=request.postEffectController
                ||request.postEffectNativeTask==null||request.postEffectPermit==null||request.readAuthorization==null
                ||request.readAuthorization!=taskAuthorization||request.background==null||!owns(request.taskId)
                ||!ownsBackground(request.taskId,request.background)||taskWeb!=null
                ||request.taskReadOrdinal!=taskObservationAdmissions)return false;
        try{
            request.postEffectPermit.requireOwner(request.postEffectNativeTask,request.readAuthorization,request.taskId,request.background.selection,request.background.generation,request.background.displayId());
            return request.postEffectPermit.transitionDeadline()==request.postEffectTransitionDeadline
                    &&request.postEffectPermit.admitted(request.postEffectRetrySubmission!=null);
        }catch(RuntimeException changed){return false;}
    }
    private void consumeObservationRetry(ObservationRequest request,NativeObservationRetryProof proof){
        long now=SystemClock.elapsedRealtime();
        if(proof.issuer!=this||!proof.taskId.equals(request.taskId)||proof.background!=request.background
                ||proof.before!=current||proof.authorization==null||proof.authorization!=taskAuthorization
                ||!owns(request.taskId)||!ownsBackground(request.taskId,request.background)||request.cancel.isCancelled()||locked(request.background)
                ||activeObservation!=null||capturePending||observationIoBusy.get()||actionWorkPending()||nativeCancellationWorkPending()
                ||request.started<proof.drainedAt||now<request.started||now>=request.deadline
                ||request.deadline>ObservationStabilityGate.requestDeadline(request.started,Long.MAX_VALUE)
                ||!proof.identity.matches(currentGraph)||!proof.consumed.compareAndSet(false,true))
            throw new IllegalStateException("failed-read ownership, clock or one-use boundary changed");
    }
    String observationTimeoutMessage(String taskId){
        ObservationRequest request=activeObservation;
        return request!=null&&request.taskId.equals(taskId)?request.diagnostic("系统屏幕观察超时")
                :"系统屏幕观察超时 [phase=callback_wait]";
    }
    boolean observationReadWorkPending(){return observationIoBusy.get()||PublicProfileBusinessRecoveryClient.workPending();}
    private boolean observationActive(ObservationRequest request){
        if(request.finished||activeObservation!=request)return false;
        if(!request.gate.requestAlive(SystemClock.elapsedRealtime(),owns(request.taskId)&&!request.cancel.isCancelled())){
            failObservation(request,"任务停止或本次观察已超时");return false;
        }
        if(locked(request.background)){failObservation(request,"当前显示范围的锁状态或后台显示凭据不可用");return false;}
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
        return new GraphBudget(){public void check(){requireObservationWork(request);}
            public Cancellation cancellation(){return request.cancel;}public long deadline(){return request.deadline;}};
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
        NativeAppEvidence.requireProfileTarget(background.profileTarget(),graph.profileWindow);
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
                catch(StaleObservation busy){request.note(ObservationDiagnostics.Event.SAMPLE_STALE_ROOT,busy.backgroundChildUnavailable);}
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
            if(request.postEffectController!=null){
                if(!postEffectObservationOwner(request))request.rejectPostEffectIdentity();
                if(request.postEffectRetrySubmission!=null&&(request.postEffectIdentityRejected
                        ||(graph!=null&&(!nativeRecheck||!request.postEffectIdentity.matches(graph))))){
                    failObservation(request,"操作后重新读取的窗口或任务身份已变化");return;
                }
            }
            if(request.initialController!=null){
                if(!initialObservationOwner(request))request.initialIdentityRejected=true;
                if(request.initialRetrySubmission!=null&&(request.initialIdentityRejected
                        ||(graph!=null&&(!nativeRecheck||!request.initialIdentity.matches(graph))))){
                    failObservation(request,"首次页面重新读取的窗口或任务身份已变化");return;
                }
            }
            NativeResampleSeed seed=request.resampleSeed;
            if(seed!=null){
                if(!seed.belongsTo(request)||seed.authorization!=taskAuthorization
                        ||!ownsBackground(request.taskId,request.background)){
                    failObservation(request,"原生复采样的授权或后台租约已变化");return;
                }
                // A foreign profile owner is terminal even if another invalidation also occurred.
                if(graph!=null)requireSameProfileOwner(seed.identity.profileWindow,graph.profileWindow);
                boolean same=request.unknownEvents==0&&seed.unknownEvents==0&&nativeRecheck
                        &&seed.identity.matches(graph)&&seed.window.matches(frozenObservationWindow(graph))
                        &&graph.readStartedElapsedMs>=seed.graphCompletedAt
                        &&graph.readCompletedElapsedMs>=graph.readStartedElapsedMs;
                if(!same){
                    request.resampleSeed=null;request.gate.resetEvidence();request.nativeSample=false;
                    if(request.trace!=null)request.trace.reset();nativeSeedDecision(request,"invalidated_before_sample");
                }else if(!seed.key.equals(frameKey(graph))){
                    request.resampleSeed=null;nativeSeedDecision(request,"replaced_by_sample");
                }
            }
            if(request.retrySubmission!=null&&graph!=null&&!request.retrySubmission.identity.matches(graph)){
                failObservation(request,"页面已切换，本次重新观察已停止");return;
            }
            if(events!=request.events||unknownEvents!=request.unknownEvents){
                if(nativeRecheck&&unknownEvents==request.unknownEvents){
                    // Target events request fresh evidence; the original gate still compares the whole observed graph.
                    request.note(ObservationDiagnostics.Event.SAMPLE_EVENT_RECHECKED);
                }else{
                    if(graph!=null){graph.close();graph=null;}request.resampleSeed=null;request.gate.resetEvidence();nativeRecheck=false;
                    request.note(ObservationDiagnostics.Event.SAMPLE_EVENT_RESET);if(request.trace!=null)request.trace.reset();
                }
            }
            // Two complete native samples are required; an earlier legacy/incomplete sample cannot seed this path.
            if(nativeRecheck!=request.nativeSample){request.resampleSeed=null;request.gate.resetEvidence();if(request.trace!=null)request.trace.reset();}
            request.nativeSample=nativeRecheck;
            long now=SystemClock.elapsedRealtime();
            ObservationStabilityGate.Result result=request.gate.sample(now,graph==null?null:frameKey(graph),true);
            if(graph==null&&request.trace!=null)request.trace.missingSample();
            request.note(ObservationDiagnostics.Event.valueOf("SAMPLE_"+result.name()));
            if(result==ObservationStabilityGate.Result.EXPIRED||result==ObservationStabilityGate.Result.CANCELLED){
                String reason="窗口仍在变化或没有活动窗口，未取得稳定观察";
                PostEffectSamplingRetry sampling=result==ObservationStabilityGate.Result.EXPIRED
                        ?postEffectSamplingCandidate(request,graph,nativeRecheck,now):null;
                if(sampling!=null){
                    graph.close();graph=null;failPostEffectObservationAfterReadDrain(request,reason,sampling);
                }else if(result==ObservationStabilityGate.Result.EXPIRED&&nativeReadRetryCandidate(request,graph)){
                    // Release this actual terminal sample before any proof or failure callback.
                    graph.close();graph=null;failObservationAfterReadDrain(request,reason);
                }else failObservation(request,reason);
                return;
            }
            rememberPostEffectSamplingFrame(request,graph,nativeRecheck,now);
            if(result==ObservationStabilityGate.Result.READY&&request.resampleSeed!=null){
                request.resampleSeed=null;nativeSeedDecision(request,"ready");
            }
            long screenshotDelay=nativeTextObservationAllowed(request,graph)?0:Math.max(0,400-(now-lastScreenshotAt));
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
    /** Reuse only copied evidence from an actual complete, unsealed post-capture graph mismatch. */
    private NativeResampleSeed nativeSavedGraphSeed(ObservationRequest request,CaptureIdentity identity,Graph graph,
                                                   long completedEvents,long completedUnknown){
        if(!identity.nativeRecheck||identity.frozenWindow==null
                ||graph==null||graph.truncated||!nativeObservationRecheckAllowed(request,graph)
                ||request.readAuthorization==null||request.readAuthorization!=taskAuthorization
                ||identity.unknownEvents!=0||completedUnknown!=0||request.unknownEvents!=0
                ||completedEvents!=request.events)return null;
        // A consumed retry may seed only this request's new, complete saved graph.
        // The failed request's frame/pixels and one-use proof are not replayed.
        if(request.retrySubmission!=null&&(!request.retrySubmission.consumed.get()
                ||request.readRecoveryRejected||!request.retrySubmission.identity.matches(graph)))return null;
        if(request.initialRetrySubmission!=null&&(!request.initialRetrySubmission.consumed.get()
                ||request.initialIdentityRejected||!initialObservationOwner(request)
                ||request.initialIdentity!=request.initialRetrySubmission.identity
                ||!request.initialRetrySubmission.identity.matches(graph)))return null;
        if(request.postEffectRetrySubmission!=null&&(!request.postEffectRetrySubmission.consumed.get()
                ||request.postEffectIdentityRejected||!postEffectObservationOwner(request)
                ||request.postEffectIdentity!=request.postEffectRetrySubmission.identity
                ||!request.postEffectRetrySubmission.identity.matches(graph)))return null;
        FrozenObservationWindow window=frozenObservationWindow(graph);
        if(window==null||!identity.frozenWindow.matches(window))return null;
        requireObservationWork(request);long now=SystemClock.elapsedRealtime();
        if(graph.readStartedElapsedMs<request.started||graph.readCompletedElapsedMs<graph.readStartedElapsedMs
                ||graph.readCompletedElapsedMs>now||now<request.started
                ||now-request.started>=ObservationStabilityGate.SETTLE_LIMIT_MS)return null;
        return new NativeResampleSeed(request,graph,window,completedEvents,completedUnknown);
    }
    private void recordSavedGraphChange(ObservationRequest request,CaptureIdentity identity,Graph graph,NativeResampleSeed seed){
        if(request.trace==null||graph==null)return;
        try{request.trace.savedGraphChange(identity.diagnosticStamp,graph.diagnosticStamp,graph.nativeObservationComplete,
                frozenObservationWindow(graph)!=null,seed!=null,SystemClock.elapsedRealtime());}
        catch(RuntimeException unavailable){/* Optional copied diagnostics never replace the observation. */}
    }
    private static void recordNativeFullGraphChange(ObservationRequest request,String stage,Graph before,Graph after){
        if(request.trace==null)return;
        try{request.trace.fullGraphChange(stage,nativeDiagnosticCensus(before),nativeDiagnosticCensus(after),SystemClock.elapsedRealtime());}
        catch(RuntimeException unavailable){/* Optional value diagnostics cannot replace the original refusal. */}
    }
    private void nativeSeedDecision(ObservationRequest request,String decision){
        if(request.trace!=null)try{request.trace.seedDecision(decision,SystemClock.elapsedRealtime());}
        catch(RuntimeException unavailable){/* A diagnostic cannot grant or retire evidence. */}
    }
    private void rememberPostEffectSamplingFrame(ObservationRequest request,Graph graph,boolean nativeRecheck,long now){
        if(request.postEffectController==null||request.postEffectRetrySubmission!=null)return;
        request.resetPostEffectSampling();
        if(!nativeRecheck||graph==null||!graph.nativeObservationComplete||graph.truncated){
            if(graph!=null)request.postEffectSamplingRejected=true;return;
        }
        if(graph.readStartedElapsedMs<request.started||graph.readCompletedElapsedMs<graph.readStartedElapsedMs
                ||graph.readCompletedElapsedMs>now){request.postEffectSamplingRejected=true;return;}
        request.postEffectSamplingIdentity=new NativeReadIdentity(graph);request.postEffectSamplingKey=frameKey(graph);
        request.postEffectSamplingStarted=graph.readStartedElapsedMs;request.postEffectSamplingCompleted=graph.readCompletedElapsedMs;
        request.postEffectSamplingAt=now;
    }
    private PostEffectSamplingRetry postEffectSamplingCandidate(ObservationRequest request,Graph graph,boolean nativeRecheck,long now){
        if(request.postEffectController==null||request.postEffectRetrySubmission!=null||!postEffectObservationOwner(request)
                ||request.initialController!=null||request.retrySubmission!=null||request.readBefore!=null||request.readIdentity!=null
                ||request.postEffectIdentity!=null||request.postEffectSamplingRejected||request.postEffectSamplingTypedChildFailures<1
                ||request.postEffectSamplingIdentity==null||request.postEffectSamplingKey==null||!nativeRecheck
                ||graph==null||!graph.nativeObservationComplete||graph.truncated||request.unknownEvents!=0
                ||request.cancel.isCancelled()||now<request.started||now-request.started<ObservationStabilityGate.SETTLE_LIMIT_MS
                ||now>=request.deadline||now>=request.postEffectTaskDeadline||now>=request.postEffectTransitionDeadline
                ||request.postEffectSamplingAt<request.started||now-request.postEffectSamplingAt<ObservationStabilityGate.SAMPLE_GAP_MS
                ||graph.readStartedElapsedMs<request.postEffectSamplingCompleted
                ||graph.readCompletedElapsedMs<graph.readStartedElapsedMs||graph.readCompletedElapsedMs>now
                ||!request.postEffectSamplingIdentity.matches(graph)||!request.postEffectSamplingKey.equals(frameKey(graph))
                ||request.readWorksStarted<1||request.readWorksStarted!=request.readWorksFinished
                ||observationIoBusy.get()||capturePending||request.shotPending||actionWorkPending()||nativeCancellationWorkPending())return null;
        return new PostEffectSamplingRetry(this,request,graph,now);
    }
    private boolean nativeReadRetryCandidate(ObservationRequest request,Graph graph){
        return request.initialController==null&&request.postEffectController==null&&request.retrySubmission==null&&request.readBefore!=null&&request.readBefore==current
                &&request.readAuthorization!=null&&request.readAuthorization==taskAuthorization
                &&request.readIdentity!=null&&!request.readRecoveryRejected&&request.readIdentity.matches(graph)
                &&nativeObservationRecheckAllowed(request,graph)&&request.unknownEvents==0
                &&request.readGraphChanges>0&&(request.readCaptureFailures>0||request.readSealedEventFailures>0)
                &&request.readWorksStarted>0&&request.readWorksStarted==request.readWorksFinished
                &&!observationIoBusy.get()&&!capturePending&&!request.shotPending
                &&!actionWorkPending()&&!nativeCancellationWorkPending();
    }
    private String retireFailedObservation(ObservationRequest request,String error){
        if(request.finished)return null;
        String diagnostic=request.diagnostic(error);
        request.note(ObservationDiagnostics.Event.REQUEST_ERROR);if(request.trace!=null)request.trace.finish("failed",SystemClock.elapsedRealtime());
        request.failedAt=SystemClock.elapsedRealtime();request.finished=true;request.resampleSeed=null;request.gate.retire();
        if(request.shotPending&&captureSerial==request.token){capturePending=false;captureSerial++;}
        request.shotPending=false;
        if(request.captured!=null){request.captured.close();request.captured=null;}
        if(activeObservation==request)activeObservation=null;
        return diagnostic;
    }
    private void failObservation(ObservationRequest request,String error){
        PostEffectSamplingRetry pending;
        synchronized(postEffectSamplingLock){pending=pendingPostEffectSampling;}
        if(pending!=null&&(pending.requestId.equals(request.requestId)
                ||request.postEffectRetrySubmission!=null&&request.postEffectRetrySubmission.samplingHandoff==pending))
            discardPostEffectSampling(pending);
        String diagnostic=retireFailedObservation(request,error);
        if(diagnostic!=null)request.callback.onError(diagnostic);
    }
    private void failObservationAfterReadDrain(final ObservationRequest request,String error){
        final int completed=request.readWorksFinished;
        final String diagnostic=retireFailedObservation(request,error);
        if(diagnostic==null)return;
        // This marker performs no read. The single-thread queue cannot run it until
        // every earlier read Runnable (including its finally and post) has returned.
        try{observationIo.execute(new Runnable(){public void run(){
            final long drainedAt=SystemClock.elapsedRealtime();
            try{main.post(new Runnable(){public void run(){
                long now=SystemClock.elapsedRealtime();
                if(!request.finished||request.readWorksStarted!=completed||request.readWorksFinished!=completed
                        ||request.captured!=null||request.shotPending||request.cancel.isCancelled()
                        ||now<drainedAt||drainedAt<request.failedAt||request.failedAt<request.started||now>=request.deadline||locked(request.background)
                        ||!owns(request.taskId)||!ownsBackground(request.taskId,request.background)
                        ||request.readBefore!=current||request.readAuthorization!=taskAuthorization
                        ||request.readIdentity==null||!request.readIdentity.matches(currentGraph)
                        ||activeObservation!=null||capturePending||observationIoBusy.get()
                        ||actionWorkPending()||nativeCancellationWorkPending()||request.unknownEvents!=0){
                    request.callback.onError(diagnostic);return;
                }
                request.callback.onReadRetryAvailable(diagnostic,new NativeObservationRetryProof(
                        live,request.readAuthorization,request.readBefore,request,drainedAt));
            }});}catch(RuntimeException unavailable){/* No main delivery means no proof; the caller's unchanged deadline wins. */}
        }});}catch(RuntimeException unavailable){request.callback.onError(diagnostic);}
    }
    private void failInitialObservationAfterReadDrain(final ObservationRequest request,String error){
        final int completed=request.readWorksFinished;
        final String diagnostic=retireFailedObservation(request,error);
        if(diagnostic==null)return;
        // The same real serial queue must return from every read before this marker.
        // It performs no read and cannot resurrect the rejected PNG or its graph.
        try{observationIo.execute(new Runnable(){public void run(){
            final long drainedAt=SystemClock.elapsedRealtime();
            try{main.post(new Runnable(){public void run(){
                long now=SystemClock.elapsedRealtime();
                if(!request.finished||request.initialRetrySubmission!=null||request.taskReadOrdinal!=1
                        ||!initialObservationOwner(request)||request.initialIdentity==null||request.initialIdentityRejected
                        ||request.readWorksStarted!=completed||request.readWorksFinished!=completed||completed<1
                        ||request.captured!=null||request.shotPending||request.resampleSeed!=null||request.cancel.isCancelled()
                        ||now<drainedAt||drainedAt<request.failedAt||request.failedAt<request.started
                        ||now>=request.deadline||now>=request.initialTaskDeadline||locked(request.background)
                        ||activeObservation!=null||capturePending||observationIoBusy.get()
                        ||actionWorkPending()||nativeCancellationWorkPending()||request.unknownEvents!=0){
                    request.callback.onError(diagnostic);return;
                }
                request.callback.onInitialReadRetryAvailable(diagnostic,new InitialObservationRetryProof(live,request,drainedAt));
            }});}catch(RuntimeException unavailable){/* No proof if main delivery fails; the original deadline wins. */}
        }});}catch(RuntimeException unavailable){request.callback.onError(diagnostic);}
    }
    private void failPostEffectObservationAfterReadDrain(final ObservationRequest request,String error){
        failPostEffectObservationAfterReadDrain(request,error,null);
    }
    private void failPostEffectObservationAfterReadDrain(final ObservationRequest request,String error,final PostEffectSamplingRetry sampling){
        final int completed=request.readWorksFinished;
        if(sampling!=null&&!registerPostEffectSampling(sampling)){failObservation(request,error);return;}
        final String diagnostic=retireFailedObservation(request,error);
        if(diagnostic==null){discardPostEffectSampling(sampling);return;}
        try{observationIo.execute(new Runnable(){public void run(){
            final long drainedAt=SystemClock.elapsedRealtime();
            try{boolean delivered=main.post(new Runnable(){public void run(){
                long now=SystemClock.elapsedRealtime();
                boolean identityRefused=sampling==null?request.postEffectIdentity==null||request.postEffectIdentityRejected
                        :request.postEffectSamplingRejected||!postEffectSamplingCurrent(sampling,now);
                if(!request.finished||request.postEffectRetrySubmission!=null||!postEffectObservationOwner(request)
                        ||identityRefused
                        ||request.readWorksStarted!=completed||request.readWorksFinished!=completed||completed<1
                        ||request.captured!=null||request.shotPending||request.resampleSeed!=null||request.cancel.isCancelled()
                        ||now<drainedAt||drainedAt<request.failedAt||request.failedAt<request.started
                        ||now>=request.deadline||now>=request.postEffectTaskDeadline||now>=request.postEffectTransitionDeadline
                        ||locked(request.background)||activeObservation!=null||capturePending||observationIoBusy.get()
                        ||actionWorkPending()||nativeCancellationWorkPending()||request.unknownEvents!=0){
                    discardPostEffectSampling(sampling);request.callback.onError(diagnostic);return;
                }
                PostEffectObservationRetryProof proof=sampling==null?new PostEffectObservationRetryProof(live,request,drainedAt)
                        :new PostEffectObservationRetryProof(live,request,drainedAt,sampling.identity,
                                "settle_expired_after_typed_child_unavailable",sampling,sampling.evidence());
                request.callback.onPostEffectReadRetryAvailable(diagnostic,proof);
            }});if(!delivered)discardPostEffectSampling(sampling);
            }catch(RuntimeException unavailable){discardPostEffectSampling(sampling);/* Undelivered drain grants no read. */}
        }});}catch(RuntimeException unavailable){discardPostEffectSampling(sampling);request.callback.onError(diagnostic);}
    }
    private void retryObservation(final ObservationRequest request,long delay){
        retryObservation(request,delay,null);
    }
    private void retryObservation(final ObservationRequest request,long delay,NativeResampleSeed seed){
        request.resetPostEffectSampling();request.resampleSeed=null;
        if(request.captured!=null){request.captured.close();request.captured=null;}
        request.gate.resetEvidence();request.nativeSample=false;request.note(ObservationDiagnostics.Event.CAPTURE_RETRY);
        if(request.trace!=null)request.trace.reset();
        if(!observationActive(request))return;
        long now=SystemClock.elapsedRealtime();
        if(seed!=null){
            boolean admit=seed.belongsTo(request)
                    &&(request.retrySubmission==null||(request.retrySubmission.consumed.get()&&!request.readRecoveryRejected))
                    &&(request.initialRetrySubmission==null||(request.initialRetrySubmission.consumed.get()
                            &&!request.initialIdentityRejected&&initialObservationOwner(request)
                            &&request.initialIdentity==request.initialRetrySubmission.identity))
                    &&(request.postEffectRetrySubmission==null||(request.postEffectRetrySubmission.consumed.get()
                            &&!request.postEffectIdentityRejected&&postEffectObservationOwner(request)
                            &&request.postEffectIdentity==request.postEffectRetrySubmission.identity))
                    &&seed.authorization==taskAuthorization&&ownsBackground(request.taskId,request.background)
                    &&seed.unknownEvents==0&&request.unknownEvents==0&&seed.events==request.events
                    &&seed.graphCompletedAt>=seed.graphStartedAt&&seed.graphCompletedAt<=now
                    &&now>=request.started&&now<request.deadline
                    &&now-request.started<ObservationStabilityGate.SETTLE_LIMIT_MS;
            if(admit){
                // Use the real main admission clock; resetEvidence never rewinds Gate.lastClock.
                ObservationStabilityGate.Result first=request.gate.sample(now,seed.key,true);
                if(first!=ObservationStabilityGate.Result.WAIT){failObservation(request,"原生复采样首证据无效");return;}
                request.nativeSample=true;request.resampleSeed=seed;nativeSeedDecision(request,"admitted");
            }else nativeSeedDecision(request,"discarded_before_admission");
        }
        request.phase("retry_gap");
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
        request.resampleSeed=null;
        if(request.nativeAxMode!=null){captureNativeAxObservation(request);return;}
        if(!observationActive(request))return;
        if(capturePending){failObservation(request,"已有截图尚未结束");return;}
        // Non-native/unknown/incomplete evidence keeps both post-capture whole-graph checks.
        // A complete native pair may be sealed before encoding; publication still checks
        // the current owned window and a final event fence, never grants action freshness.
        final CaptureIdentity identity=new CaptureIdentity(request.captured,SystemClock.elapsedRealtime(),
                request.eventWatermark(),request.nativeSample&&nativeObservationRecheckAllowed(request,request.captured));
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
        final long callbackAt=SystemClock.elapsedRealtime();
        if(!observationIoBusy.compareAndSet(false,true)){
            result.getHardwareBuffer().close();failObservation(request,"先前屏幕读取尚未退出");return;
        }
        request.worker(true);
        try{observationIo.execute(new Runnable(){public void run(){
            final ObservationProduct product=new ObservationProduct(identity,callbackAt);Graph after=null;
            boolean copyEntered=false,retry=false;String error=null;
            try{
                requireObservationWork(request);request.phase("screenshot_copy");copyEntered=true;
                product.bitmap=copyScreenshot(result);requireObservationWork(request);
                request.phase("screenshot_graph");
                product.pairStartedAt=SystemClock.elapsedRealtime();
                final ObservationEventWatermark pairStart=request.eventWatermark();
                product.pairEvents=pairStart.events;final long pairUnknownEvents=pairStart.unknownEvents;
                try{after=readGraph(observationBudget(request),request.background);}
                catch(NoActiveWindow busy){request.note(ObservationDiagnostics.Event.SCREENSHOT_GRAPH_MISSING);retry=true;}
                catch(StaleObservation busy){request.note(ObservationDiagnostics.Event.SCREENSHOT_GRAPH_STALE,busy.backgroundChildUnavailable);retry=true;}
                // Freeze the read endpoint before diagnostics or pure comparison.
                // A later event is not covered by this completed raw census.
                final ObservationEventWatermark pairEnd=request.eventWatermark();
                final long completedPairEvents=pairEnd.events,completedPairUnknown=pairEnd.unknownEvents;
                product.pairCompletedWatermark=pairEnd;product.formPairCompletedEvents=completedPairEvents;
                product.pairCompletedAt=SystemClock.elapsedRealtime();
                request.graph("screenshot_graph",after);
                if(!retry&&!identity.matches(after))product.formPair=nativeCtripFormPair(request,identity,after);
                if(!retry&&!identity.matches(after)&&product.formPair==null){request.note(ObservationDiagnostics.Event.SCREENSHOT_GRAPH_CHANGED);retry=true;
                    // The rejected pixels are never published. This complete fresh read may
                    // only seed the next same-request pair; all later reads/capture stay new.
                    product.seed=nativeSavedGraphSeed(request,identity,after,request.events,request.unknownEvents);
                    if(product.seed!=null)request.note(ObservationDiagnostics.Event.SCREENSHOT_GRAPH_SEED_CANDIDATE);
                    recordNativeFullGraphChange(request,"screenshot_graph",request.captured,after);}
                product.nativeGraphRechecked=product.formPair==null&&!retry&&identity.nativeRecheck&&nativeObservationRecheckAllowed(request,after);
                // A scoped historical pair may span known target events only when ALL
                // actual census differences were classified. Unknown events still veto.
                boolean scopedPair=product.formPair!=null&&identity.unknownEvents==0&&pairUnknownEvents==0
                        &&completedPairUnknown==0&&request.unknownEvents==0
                        &&product.pairEvents>=identity.events&&completedPairEvents>=product.pairEvents;
                // New content coverage requires actual equal complete graphs. Any event after
                // this census endpoint, unknown event or window boundary still refuses the seal.
                boolean contentPair=product.nativeGraphRechecked&&pairEnd.onlyContentSince(pairStart)
                        &&pairEnd.onlyContentSince(identity.eventWatermark)&&completedPairEvents==request.events;
                if((product.nativeGraphRechecked||scopedPair)&&identity.frozenWindow!=null
                        &&identity.frozenWindow.matches(frozenObservationWindow(after))
                        &&request.readAuthorization!=null&&request.readAuthorization==taskAuthorization
                        &&(scopedPair||contentPair?completedPairEvents==request.events:product.pairEvents==request.events)&&pairUnknownEvents==request.unknownEvents
                        &&pairEnd.sameBoundary(identity.eventWatermark)
                        &&identity.unknownEvents==request.unknownEvents
                        &&identity.graphStartedAt>=request.started&&identity.graphCompletedAt>=identity.graphStartedAt
                        &&identity.graphCompletedAt<=identity.capturedAt&&identity.capturedAt<=callbackAt
                        &&callbackAt<=product.pairStartedAt&&product.pairStartedAt<=product.pairCompletedAt){
                    requireObservationWork(request);
                    product.seal=new ObservationPairSeal(identity,request.readAuthorization,product.pairStartedAt,
                            product.pairCompletedAt,SystemClock.elapsedRealtime(),scopedPair||contentPair?completedPairEvents:product.pairEvents,pairUnknownEvents);
                    product.contentPairSealed=contentPair&&completedPairEvents!=product.pairEvents;
                }
                if(product.formPair!=null&&product.seal==null)retry=true;
                if(after!=null){after.close();after=null;}
                if(!retry){
                    if(product.bitmap.getWidth()<1||product.bitmap.getHeight()<1||(long)product.bitmap.getWidth()*product.bitmap.getHeight()>16000000L)
                        throw new IllegalStateException("屏幕尺寸超出观察范围");
                    requireObservationWork(request);
                    if(!request.directory.isDirectory())throw new IllegalStateException("任务证据目录不存在");
                    product.id=UUID.randomUUID().toString().replace("-","");File path=new File(request.directory,product.id+".png");
                    if(!path.createNewFile())throw new IllegalStateException("观察标识重复");
                    product.path=path; // Only a file actually created by this request may be removed.
                    request.phase("png_encode");product.encodeStartedAt=SystemClock.elapsedRealtime();
                    try(FileOutputStream stream=new FileOutputStream(path)){
                        if(!product.bitmap.compress(Bitmap.CompressFormat.PNG,100,stream))throw new IllegalStateException("截图编码失败");
                        product.encodeCompletedAt=SystemClock.elapsedRealtime();
                        requireObservationWork(request);request.phase("png_fsync");stream.getFD().sync();
                    }
                    requireObservationWork(request);
                    path.setReadable(false,false);path.setReadable(true,true);path.setWritable(false,false);path.setWritable(true,true);
                    request.phase("png_hash");product.digest=fileSha256(path);requireObservationWork(request);
                    product.persistedAt=SystemClock.elapsedRealtime();
                    // Keep the existing diagnostic phase bucket; captureEvidence records
                    // whether this was a full graph or an identity-only publication check.
                    request.phase("saved_graph");
                    product.checkedEvents=request.events;product.publicationCheckStartedAt=SystemClock.elapsedRealtime();
                    ObservationEventWatermark persistedEvents=request.eventWatermark();
                    if(request.postEffectController!=null&&product.formPair!=null&&product.seal!=null
                            &&persistedEvents.events!=product.seal.events)retry=true;
                    boolean completeContentCheck=product.seal!=null&&product.formPair==null&&identity.nativeRecheck
                            &&persistedEvents.contentEvents>identity.eventWatermark.contentEvents;
                    if(completeContentCheck){
                        // Typed content events never advance a window-only watermark. Encoding is
                        // already finished: reread the COMPLETE actual graph and window census.
                        product.postEncodingStartWatermark=persistedEvents;
                        try{after=readGraph(observationBudget(request),request.background);}
                        catch(NoActiveWindow busy){request.note(ObservationDiagnostics.Event.SAVED_GRAPH_MISSING);retry=true;}
                        catch(StaleObservation busy){request.note(ObservationDiagnostics.Event.SAVED_GRAPH_STALE);retry=true;}
                        final ObservationEventWatermark complete=request.eventWatermark();
                        product.postEncodingCompletedWatermark=complete;
                        request.graph("saved_graph",after);
                        boolean equal=!retry&&after!=null&&identity.matches(after)
                                &&nativeObservationRecheckAllowed(request,after)
                                &&identity.frozenWindow.matches(frozenObservationWindow(after));
                        boolean eventsCovered=!retry&&complete.onlyContentSince(persistedEvents)
                                &&complete.onlyContentSince(identity.eventWatermark)&&complete.events==request.events;
                        // Pixels already match A and B. A later, complete C may establish a
                        // historical first form only for the already-entered OPEN's read permit.
                        if(!equal&&eventsCovered&&request.postEffectController!=null)
                            product.postEncodingFormPair=nativeCtripFormPair(request,identity,after);
                        boolean formCovered=product.postEncodingFormPair!=null&&complete.events==request.events;
                        boolean covered=equal&&eventsCovered;
                        if(!retry&&!equal&&!formCovered){
                            request.note(ObservationDiagnostics.Event.SAVED_GRAPH_CHANGED);retry=true;
                            product.seed=nativeSavedGraphSeed(request,identity,after,complete.events,complete.unknownEvents);
                            recordSavedGraphChange(request,identity,after,product.seed);
                            recordNativeFullGraphChange(request,"saved_graph",request.captured,after);
                        }
                        if(!covered&&!formCovered)retry=true;
                        product.postEncodingCompleteNativeRechecked=covered;
                        product.wholeGraphRechecked=covered;product.nativeGraphRechecked=covered;
                        product.frozenWindowRechecked=covered||formCovered;
                        if(covered||formCovered)product.checkedEvents=complete.events;
                    }else if(product.seal!=null){
                        // Content changes since the sealed pair do not rewrite historical facts.
                        // This still reads actual permission/root/window/geometry/census facts.
                        product.nativeGraphRechecked=false;
                        try{product.frozenWindowRechecked=identity.frozenWindow.matches(readFrozenObservationWindow(request,identity));}
                        catch(NoActiveWindow busy){request.note(ObservationDiagnostics.Event.SAVED_GRAPH_MISSING);retry=true;}
                        catch(StaleObservation busy){request.note(ObservationDiagnostics.Event.SAVED_GRAPH_STALE);retry=true;}
                        if(!retry&&!product.frozenWindowRechecked){
                            if(request.initialController!=null)request.initialIdentityRejected=true;
                            if(request.postEffectController!=null)request.rejectPostEffectIdentity();
                            request.note(ObservationDiagnostics.Event.SAVED_GRAPH_CHANGED);retry=true;
                        }
                    }else{
                        // Unknown/Web/incomplete or event-inconsistent pairs keep the old full-graph contract.
                        try{after=readGraph(observationBudget(request),request.background);}
                        catch(NoActiveWindow busy){request.note(ObservationDiagnostics.Event.SAVED_GRAPH_MISSING);retry=true;}
                        catch(StaleObservation busy){request.note(ObservationDiagnostics.Event.SAVED_GRAPH_STALE);retry=true;}
                        final long completedEvents=request.events,completedUnknown=request.unknownEvents;
                        request.graph("saved_graph",after);
                        if(!retry&&!identity.matches(after)){
                            request.note(ObservationDiagnostics.Event.SAVED_GRAPH_CHANGED);retry=true;
                            product.seed=nativeSavedGraphSeed(request,identity,after,completedEvents,completedUnknown);
                            recordSavedGraphChange(request,identity,after,product.seed);
                            recordNativeFullGraphChange(request,"saved_graph",request.captured,after);
                        }
                        product.wholeGraphRechecked=!retry&&after!=null&&identity.matches(after);
                        product.nativeGraphRechecked=product.nativeGraphRechecked&&product.wholeGraphRechecked&&nativeObservationRecheckAllowed(request,after);
                    }
                    product.publicationCheckCompletedAt=SystemClock.elapsedRealtime();
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
    /** Read-failure classification only. The unpublished pair is still discarded.
     * A known target-display event after the current-window check's watermark is
     * distinct from missing/changed identity, unknown events or an unsealed pair. */
    private boolean nativeLateEventReadFailure(ObservationRequest request,ObservationProduct product,boolean retry){
        if(retry||request.retrySubmission!=null||request.readRecoveryRejected
                ||request.readBefore==null||request.readBefore!=current
                ||request.readAuthorization==null||request.readAuthorization!=taskAuthorization
                ||request.readIdentity==null||product.seal==null||product.seal.identity!=product.identity
                ||product.seal.authorization!=request.readAuthorization||!product.identity.nativeRecheck
                ||!product.frozenWindowRechecked
                ||product.events<0||product.seal.events<product.events||product.checkedEvents<product.seal.events
                ||request.events<=product.checkedEvents
                ||product.unknownEvents!=0||product.seal.unknownEvents!=0||request.unknownEvents!=0)return false;
        return request.readIdentity.matches(request.captured)&&product.identity.matches(request.captured)
                &&nativeObservationRecheckAllowed(request,request.captured);
    }
    /** Initial read only. A current complete sealed pair was discarded for a later
     * known target event after its successful post-persistence window check.
     * Earlier missing startup samples do not authorize this proof or replace the pair. */
    private boolean initialLateEventReadFailure(ObservationRequest request,ObservationProduct product,boolean retry){
        long now=SystemClock.elapsedRealtime();
        if(retry||request.initialController==null||request.initialRetrySubmission!=null||request.taskReadOrdinal!=1
                ||!initialObservationOwner(request)||request.initialIdentity!=null||request.initialIdentityRejected
                ||request.readBefore!=null||request.readIdentity!=null||request.retrySubmission!=null
                ||now<request.started||now-request.started<ObservationStabilityGate.SETTLE_LIMIT_MS
                ||now>=request.deadline||now>=request.initialTaskDeadline
                ||product.seal==null||product.seal.identity!=product.identity
                ||product.seal.authorization!=request.readAuthorization||!product.identity.nativeRecheck
                ||!product.frozenWindowRechecked||product.bitmap==null||product.path==null||product.digest==null
                ||product.persistedAt<product.seal.sealedAt||product.publicationCheckStartedAt<product.persistedAt
                ||product.publicationCheckCompletedAt<product.publicationCheckStartedAt||product.publicationCheckCompletedAt>now
                ||product.events<0||product.seal.events<product.events||product.checkedEvents<product.seal.events
                ||request.events<=product.checkedEvents
                ||product.unknownEvents!=0||product.seal.unknownEvents!=0||request.unknownEvents!=0
                ||request.readWorksStarted<1||request.readWorksStarted!=request.readWorksFinished
                ||observationIoBusy.get()||capturePending||request.shotPending
                ||actionWorkPending()||nativeCancellationWorkPending())return false;
        return product.identity.matches(request.captured)&&nativeObservationRecheckAllowed(request,request.captured);
    }
    /** Only an already accepted OPEN navigation can replace this first read
     * after the current sealed capture passes its window check but a later
     * known target event still makes the original publication fence reject it. */
    private boolean postEffectLateEventReadFailure(ObservationRequest request,ObservationProduct product,boolean retry){
        long now=SystemClock.elapsedRealtime();
        if(retry||request.postEffectController==null||request.postEffectRetrySubmission!=null
                ||!postEffectObservationOwner(request)||request.postEffectIdentity!=null||request.postEffectIdentityRejected
                ||request.initialController!=null||request.readBefore!=null||request.readIdentity!=null||request.retrySubmission!=null
                ||now<request.started
                ||now>=request.deadline||now>=request.postEffectTaskDeadline||now>=request.postEffectTransitionDeadline
                ||product.seal==null||product.seal.identity!=product.identity
                ||product.seal.authorization!=request.readAuthorization||!product.identity.nativeRecheck
                ||!product.frozenWindowRechecked||product.bitmap==null||product.path==null||product.digest==null
                ||product.persistedAt<product.seal.sealedAt||product.publicationCheckStartedAt<product.persistedAt
                ||product.publicationCheckCompletedAt<product.publicationCheckStartedAt||product.publicationCheckCompletedAt>now
                ||product.events<0||product.seal.events<product.events||product.checkedEvents<product.seal.events
                ||request.events<=product.checkedEvents
                ||product.unknownEvents!=0||product.seal.unknownEvents!=0||request.unknownEvents!=0
                ||request.readWorksStarted<1||request.readWorksStarted!=request.readWorksFinished
                ||observationIoBusy.get()||capturePending||request.shotPending
                ||actionWorkPending()||nativeCancellationWorkPending())return false;
        return product.identity.matches(request.captured)&&nativeObservationRecheckAllowed(request,request.captured);
    }
    /** Re-run the existing publication identity check once, on the same serial
     * worker and within the same request. This is not another content sample,
     * frame refresh or action permit; the original pair and capture age remain. */
    private boolean recheckPostEffectPublication(final ObservationRequest request,final ObservationProduct product){
        if(request.postEffectPublicationRecheckAttempted||!postEffectLateEventReadFailure(request,product,false))return false;
        if(!observationIoBusy.compareAndSet(false,true))return false;
        request.postEffectPublicationRecheckAttempted=true;
        product.firstPublicationCheckStartedAt=product.publicationCheckStartedAt;
        product.firstPublicationCheckCompletedAt=product.publicationCheckCompletedAt;
        product.firstPublicationCheckEvents=product.checkedEvents;
        product.postEffectPublicationRechecks=1;
        request.note(ObservationDiagnostics.Event.POST_EFFECT_WINDOW_RECHECK_STARTED);
        request.phase("publication_window_recheck");request.worker(true);
        try{
            observationIo.execute(new Runnable(){public void run(){
                boolean matched=false;String error=null;
                try{
                    requireObservationWork(request);
                    if(!postEffectObservationOwner(request)||request.postEffectIdentityRejected)
                        throw new StaleObservation("late-event publication recheck owner changed");
                    product.checkedEvents=request.events;
                    product.publicationCheckStartedAt=SystemClock.elapsedRealtime();
                    if(request.unknownEvents!=0)throw new StaleObservation("late-event publication recheck has unknown events");
                    matched=product.identity.frozenWindow.matches(readFrozenObservationWindow(request,product.identity));
                    product.frozenWindowRechecked=matched;
                    if(!matched){request.rejectPostEffectIdentity();request.note(ObservationDiagnostics.Event.SAVED_GRAPH_CHANGED);}
                    requireObservationWork(request);
                    boolean fence=matched&&product.checkedEvents==request.events&&request.unknownEvents==0;
                    request.note(fence?ObservationDiagnostics.Event.POST_EFFECT_WINDOW_RECHECK_PASSED
                            :ObservationDiagnostics.Event.POST_EFFECT_WINDOW_RECHECK_REJECTED);
                }catch(NoActiveWindow missing){
                    product.frozenWindowRechecked=false;request.note(ObservationDiagnostics.Event.SAVED_GRAPH_MISSING);
                }catch(StaleObservation changed){
                    product.frozenWindowRechecked=false;request.rejectPostEffectIdentity();
                    request.note(ObservationDiagnostics.Event.SAVED_GRAPH_STALE);
                }catch(Exception failure){error="操作后窗口重验失败："+message(failure);}
                finally{
                    product.publicationCheckCompletedAt=SystemClock.elapsedRealtime();
                    request.worker(false);observationIoBusy.set(false);
                }
                final boolean retry=!matched;final String failure=error;boolean posted=false;
                try{posted=main.post(new Runnable(){public void run(){acceptScreenshot(request,product,retry,failure);}});}
                finally{if(!posted)product.close();}
            }});
            return true;
        }catch(RuntimeException unavailable){
            request.worker(false);observationIoBusy.set(false);
            request.note(ObservationDiagnostics.Event.POST_EFFECT_WINDOW_RECHECK_REJECTED);
            return false;
        }
    }
    private void acceptScreenshot(ObservationRequest request,ObservationProduct product,boolean retry,String error){
        boolean transferred=false;
        try{
            if(!observationActive(request))return;
            if(error!=null){failObservation(request,error);return;}
            if((request.postEffectRetrySubmission!=null||request.postEffectController!=null
                    &&(product.formPair!=null||product.postEncodingFormPair!=null))
                    &&(!postEffectObservationOwner(request)||request.postEffectIdentityRejected)){
                failObservation(request,"操作后重新读取的窗口或任务身份已变化");return;
            }
            if(request.initialRetrySubmission!=null&&(!initialObservationOwner(request)||request.initialIdentityRejected)){
                failObservation(request,"首次页面重新读取的窗口或任务身份已变化");return;
            }
            if(request.retrySubmission!=null&&request.readRecoveryRejected){
                failObservation(request,"页面已切换，本次重新观察已停止");return;
            }
            if(product.seal!=null&&(product.seal.identity!=product.identity
                    ||product.seal.authorization!=request.readAuthorization||product.seal.authorization!=taskAuthorization
                    ||!ownsBackground(request.taskId,request.background))){
                failObservation(request,"封存观察的授权或后台窗口租约已变化");return;
            }
            if(product.seal!=null)requireTaskAuthorization(request.taskId,taskAuthorization);
            ObservationEventWatermark publicationEvents=request.eventWatermark();
            if(!publicationEvents.sameBoundary(product.identity.eventWatermark))retry=true;
            boolean sealedEventFailure=nativeLateEventReadFailure(request,product,retry);
            boolean initialEventFailure=initialLateEventReadFailure(request,product,retry);
            boolean postEffectEventFailure=postEffectLateEventReadFailure(request,product,retry);
            // The legacy window-only retry cannot credit typed events after a complete census.
            // Such a pair must be discarded; any subsequent read starts with new complete evidence.
            if(postEffectEventFailure&&publicationEvents.contentEvents==product.identity.eventWatermark.contentEvents
                    &&recheckPostEffectPublication(request,product)){transferred=true;return;}
            boolean eventsChanged=product.events!=request.events||product.unknownEvents!=request.unknownEvents;
            boolean currentCheck=product.seal==null?product.nativeGraphRechecked:product.frozenWindowRechecked;
            boolean eventsRechecked=eventsChanged&&currentCheck
                    &&product.unknownEvents==request.unknownEvents&&product.checkedEvents==request.events
                    &&nativeObservationRecheckAllowed(request,request.captured);
            if(product.seal!=null&&(!product.frozenWindowRechecked||product.checkedEvents!=request.events
                    ||product.unknownEvents!=request.unknownEvents))retry=true;
            if(retry||(eventsChanged&&!eventsRechecked)){
                if(sealedEventFailure)request.readSealedEventFailures++;
                if(eventsChanged)request.note(ObservationDiagnostics.Event.CAPTURE_EVENT_RESET);
                NativeResampleSeed seed=product.seed;
                if(initialEventFailure)request.initialIdentity=new NativeReadIdentity(request.captured);
                if(postEffectEventFailure)request.postEffectIdentity=new NativeReadIdentity(request.captured);
                product.close(); // Old pixels/file never accompany the copied first sample.
                if(initialEventFailure){
                    request.note(ObservationDiagnostics.Event.CAPTURE_RETRY);
                    failInitialObservationAfterReadDrain(request,"首次页面仍在变化，当前截图未发布");return;
                }
                if(postEffectEventFailure){
                    request.note(ObservationDiagnostics.Event.CAPTURE_RETRY);
                    failPostEffectObservationAfterReadDrain(request,"操作后页面仍在变化，当前截图未发布");return;
                }
                // A discarded post-navigation screenshot requires a new pair even when it seeds
                // the first sample. Starting another Binder read cannot satisfy a sub-gap budget.
                long remaining=request.deadline-SystemClock.elapsedRealtime();
                if(request.postEffectController!=null&&remaining<=ObservationStabilityGate.SAMPLE_GAP_MS){
                    failObservation(request,"操作后的页面仍在变化，本次观察剩余时间不足以重新采样");return;
                }
                retryObservation(request,200,seed);return;
            }
            if(eventsRechecked)request.note(ObservationDiagnostics.Event.CAPTURE_EVENT_RECHECKED);
            request.phase("publish");
            Graph graph=request.captured;
            if(graph==null||product.bitmap==null||product.path==null||product.digest==null)
                throw new IllegalStateException("观察结果所有权不完整");
            if(!observationActive(request))return;
            PhoneObservation observation=new PhoneObservation(product.id,graph.packageName,product.capturedAt,
                    product.bitmap.getWidth(),product.bitmap.getHeight(),graph.rotation,graph.windowId,graph.bounds,product.path,product.digest,graph.digest,graph.state,graph.windowMetadata,graph.truncated,graph.rows,graph.backgroundGeneration,graph.backgroundBootstrapPackage,graph.backgroundAllowedPackages,graph.collectionStats,
                    graph.backgroundSelectionRaw==null?null:new JSONObject(graph.backgroundSelectionRaw),graph.backgroundOwnerSha,
                    product.captureEvidence(SystemClock.elapsedRealtime()),graph.profileWindow);
            clearSnapshot();current=observation;currentGraph=graph;currentBitmap=product.bitmap;
            request.captured=null;product.bitmap=null;product.published=true;
            if(request.trace!=null)request.trace.published(observation.id,SystemClock.elapsedRealtime());
            request.finished=true;request.gate.retire();activeObservation=null;
            request.callback.onObservation(observation);
        }catch(Exception failure){failObservation(request,"观察发布失败："+message(failure));}
        finally{if(!transferred)product.close();}
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
    /** A separate historical planning channel. It never writes current/currentGraph. */
    private volatile NativeSearchSession nativeSearchSession;
    private volatile NativeSearchRequest activeNativeSearchObservation;
    private volatile NativeSearchRequest nativeSearchRetryPending;
    private boolean nativeSearchPlanningAdmitted;
    private File nativeSearchPlanningDirectory;
    // One memory-only tracker survives action drain until the one successor read
    // is admitted. Event callback routing/handoff is atomic and never suppresses events.
    private final Object nativeSearchEventLock=new Object();
    private SearchActionWork nativeSearchTrackedAction;
    private CalendarFreshObservation nativeCalendarTracked;
    // Read-only initial sampling history. This reference never grants a planning/effect capability.
    private NativeSearchRequest nativeSearchSamplingTracked;

    synchronized void bindNativeSearchSession(NativeSearchSession session){
        if(session==null||nativeSearchSession!=null||nativeSearchPlanningAdmitted||taskObservationAdmissions!=0
                ||live!=this||ownedController!=session.controller||!ownsAuthorization(session.taskId,session.authorization)
                ||!ownsBackground(session.taskId,session.background)||taskScope==null||taskScope.restricted()||taskWeb!=null
                ||nativeAxMode==null||nativeAxMode.controller!=session.controller||nativeAxMode.nativeTask!=session.nativeTask
                ||nativeAxMode.authorization!=session.authorization||nativeAxMode.background!=session.background
                ||activeObservation!=null||activeNativeSearchObservation!=null||capturePending
                ||observationReadWorkPending()||actionWorkPending()||nativeCancellationWorkPending())
            throw new IllegalStateException("native search requires the actual idle text controller/Session/lease");
        session.requireLive(SystemClock.elapsedRealtime());nativeSearchSession=session;nativeSearchPlanningDirectory=null;
    }
    private synchronized boolean nativeSearchSessionCurrent(NativeSearchSession session,QualificationScopeConfig.Bound scope){
        return session!=null&&session==nativeSearchSession&&live==this&&ownedController==session.controller
                &&ownsScope(session.taskId,scope)&&!scope.restricted()&&ownsAuthorization(session.taskId,session.authorization)
                &&ownsBackground(session.taskId,session.background)&&taskWeb==null
                &&nativeAxMode!=null&&nativeAxMode.controller==session.controller&&nativeAxMode.nativeTask==session.nativeTask
                &&nativeAxMode.authorization==session.authorization&&nativeAxMode.background==session.background;
    }
    private boolean nativeSearchAllowsLegacyObservation(String taskId){
        NativeSearchSession session=nativeSearchSession;
        return activeNativeSearchObservation==null&&(session==null||!session.taskId.equals(taskId)||session.navigationEffectRecorded());
    }
    /** Only counters from actual service callbacks; no node traversal occurs here. */
    private static final class SearchEvents {
        final int display;final String packageName;volatile int window=-1;
        private long events,unknown,content,boundary;
        SearchEvents(int display,String packageName){this.display=display;this.packageName=packageName;}
        synchronized void event(int actualDisplay,int actualWindow,String actualPackage,boolean contentType,boolean typed){
            if(actualDisplay>=0&&actualDisplay!=display)return;
            events++;if(actualDisplay<0)unknown++;
            if(!typed)return;
            if(actualDisplay>=0&&contentType&&window>=0&&actualWindow==window&&packageName.equals(actualPackage))content++;
            else boundary++;
        }
        synchronized NativeSearchPlanning.EventMark mark(){return new NativeSearchPlanning.EventMark(events,unknown,content,boundary);}
    }
    private static boolean sameSearchEvents(NativeSearchPlanning.EventMark a,NativeSearchPlanning.EventMark b){
        return a!=null&&b!=null&&a.events==b.events&&a.unknown==b.unknown&&a.content==b.content&&a.boundary==b.boundary;
    }
    private void noteNativeSearchEvent(int display,int window,String pkg,boolean content,boolean typed){
        synchronized(nativeSearchEventLock){
            NativeSearchRequest request=activeNativeSearchObservation;
            if(request!=null&&!request.finished)request.events.event(display,window,pkg,content,typed);
            NativeSearchRequest retry=nativeSearchRetryPending;
            if(retry!=null&&(retry!=request||request.finished))retry.events.event(display,window,pkg,content,typed);
            NativeSearchRequest sampling=nativeSearchSamplingTracked;
            if(sampling!=null&&sampling!=retry&&(sampling!=request||request.finished))
                sampling.events.event(display,window,pkg,content,typed);
            CalendarFreshObservation calendar=nativeCalendarTracked;
            if(calendar!=null)calendar.inputEvents.event(display,window,pkg,content,typed);
            SearchActionWork action=nativeSearchTrackedAction;
            if(action!=null)action.events.event(display,window,pkg,content,typed);
        }
    }
    private void registerNativeSearchActionTracker(SearchActionWork work){
        synchronized(nativeSearchEventLock){
            if(nativeSearchTrackedAction!=null)throw new IllegalStateException("previous search event tracker still owns admission");
            nativeSearchTrackedAction=work;
        }
    }
    private void clearNativeSearchActionTracker(SearchActionWork work){
        synchronized(nativeSearchEventLock){if(nativeSearchTrackedAction==work)nativeSearchTrackedAction=null;}
    }
    /** Only a local original sampling fence constructs this cause. It is deliberately
     * not a StaleObservation: the inner resampling catch must never swallow it. */
    private static final class NativeSearchSamplingExhausted extends IllegalStateException {
        private static final long serialVersionUID=1L;
        final NativeSearchRequest request;final long observedElapsed;final String fence;
        private NativeSearchSamplingExhausted(NativeSearchRequest request,long at,String fence){
            super("original native planning sampling deadline reached; no planning was produced");
            this.request=request;observedElapsed=at;this.fence=fence;
        }
    }
    private static final class NativeSearchSamplingAnchor {
        final Map<String,Object> identity,evidence;
        final NativeSearchPlanning.EventMark baseline;
        NativeSearchSamplingAnchor(NativeSearchSample a,NativeSearchSample b,NativeSearchPlanning.Timing timing,
                NativeSearchPlanning.CaptureContext context){
            context.require(a.snapshot,b.snapshot,timing);
            Map<String,Object> first=nativeSearchSamplingIdentity(a.snapshot),second=nativeSearchSamplingIdentity(b.snapshot);
            if(!first.equals(second))throw new IllegalStateException("historical full-read ownership differs");
            baseline=a.before;
            requireNativeSearchSamplingMarks(baseline,a.after,b.before,b.after,context.sealed);
            identity=second;
            Map<String,Object> e=new LinkedHashMap<String,Object>();
            e.put("schema","hepta.native-search-sampling-owner-anchor.v1");e.put("identity",identity);
            e.put("first_census_sha256",a.snapshot.sha);e.put("second_census_sha256",b.snapshot.sha);
            e.put("timing",timing.evidence());e.put("source_context",context.evidence());
            e.put("baseline_watermark",baseline.evidence());e.put("historical_only",true);
            e.put("pair_accepted_for_planning",false);e.put("current_profile_authority",false);
            evidence=NativeAppEvidence.immutableMap(e);
        }
    }
    private static Map<String,Object> nativeSearchSamplingIdentity(NativeActionSnapshotCheck.Snapshot value){
        Map<String,Object> identity=new java.util.TreeMap<String,Object>(NativeSearchRole.stableEnvelope(value));
        identity.remove("origin_observation_id");return NativeAppEvidence.immutableMap(identity);
    }
    private static void requireNativeSearchSamplingMarks(NativeSearchPlanning.EventMark baseline,
            NativeSearchPlanning.EventMark... later){
        if(baseline==null||baseline.unknown!=0||baseline.events-baseline.content-baseline.boundary!=0)
            throw new IllegalStateException("sampling history contains unknown or untyped events");
        NativeSearchPlanning.EventMark previous=baseline;
        for(NativeSearchPlanning.EventMark current:later){
            if(current==null||!current.monotonicSince(previous)||current.unknown!=0
                    ||current.boundary!=baseline.boundary||current.events-current.content-current.boundary!=0
                    ||current.events-baseline.events!=current.content-baseline.content)
                throw new IllegalStateException("sampling history crossed its fixed historical event boundary");
            previous=current;
        }
    }
    private static void disqualifyNativeSearchSampling(NativeSearchRequest request,String reason){
        synchronized(request){if(request.samplingDisqualified==null)request.samplingDisqualified=reason;}
    }
    private void noteNativeSearchSamplingAnchor(NativeSearchRequest request,NativeSearchSample a,NativeSearchSample b,
            NativeSearchPlanning.Timing timing,NativeSearchPlanning.CaptureContext context){
        synchronized(nativeSearchEventLock){
            if(nativeSearchSamplingTracked!=request||request.samplingDisqualified!=null)return;
            try{
                NativeSearchSamplingAnchor next=new NativeSearchSamplingAnchor(a,b,timing,context);
                if(request.samplingAnchor==null){
                    request.samplingAnchor=next;request.samplingLastVerified=context.sealed;
                }else{
                    if(!request.samplingAnchor.identity.equals(next.identity))
                        throw new IllegalStateException("later complete ownership differs from the earliest sampling anchor");
                    requireNativeSearchSamplingMarks(request.samplingAnchor.baseline,request.samplingLastVerified,
                            a.before,a.after,b.before,b.after,context.sealed);
                    request.samplingLastVerified=context.sealed;
                }
            }catch(RuntimeException refused){disqualifyNativeSearchSampling(request,message(refused));}
        }
    }
    private boolean nativeSearchSamplingHistoryLocked(NativeSearchRequest request){
        if(request.samplingAnchor==null||request.samplingDisqualified!=null)return false;
        try{
            NativeSearchPlanning.EventMark current=request.events.mark();
            requireNativeSearchSamplingMarks(request.samplingAnchor.baseline,request.samplingLastVerified,current);
            if(request.failureWatermark!=null)
                requireNativeSearchSamplingMarks(request.samplingAnchor.baseline,request.failureWatermark,current);
            request.samplingLastVerified=current;return true;
        }catch(RuntimeException refused){disqualifyNativeSearchSampling(request,message(refused));return false;}
    }
    private void closeNativeSearchSampling(NativeSearchRequest request){
        synchronized(nativeSearchEventLock){
            NativeSearchRequest original=request.samplingSubmission==null?request:request.samplingSubmission.failed;
            original.samplingTrackingClosed=true;original.samplingRecoveryPending=false;
            if(original.samplingIssued!=null)original.samplingIssued.closed=true;
            if(nativeSearchSamplingTracked==original)nativeSearchSamplingTracked=null;
        }
    }
    /** One inspection permit after local sampling exhaustion, not a loading
     * classification, a current profile proof, a planning frame, or an effect permit. */
    static final class NativeSearchSamplingExhaustionProof {
        private final HeptaAccessibilityService issuer;private final NativeSearchRequest failed;
        private final NativeSearchSession session;private final long drainedAt,issuedAt;
        private final java.util.concurrent.atomic.AtomicBoolean consumed=new java.util.concurrent.atomic.AtomicBoolean();
        private volatile boolean closed;private NativeSearchRequest admitted;
        private NativeSearchSamplingExhaustionProof(HeptaAccessibilityService issuer,NativeSearchRequest failed,long drained,long issued){
            this.issuer=issuer;this.failed=failed;session=failed.session;drainedAt=drained;issuedAt=issued;
        }
        private void requireLocked(long now){
            if(closed||consumed.get()||failed.samplingIssued!=this||issuer.nativeSearchSamplingTracked!=failed
                    ||failed.samplingTrackingClosed||!failed.samplingRecoveryPending||!failed.finished||!failed.workerDrained
                    ||failed.published||failed.path!=null||failed.lastCompletePair!=null||failed.samplingExhaustion==null
                    ||failed.samplingExhaustion.request!=failed||failed.samplingDiagnosticSha==null
                    ||failed.retrySubmission!=null||failed.replanSubmission!=null||failed.samplingSubmission!=null
                    ||now<issuedAt||issuedAt<drainedAt||drainedAt<failed.failureElapsed
                    ||failed.failureElapsed<failed.samplingExhaustion.observedElapsed
                    ||now>=failed.deadline||now>=session.chainDeadlineElapsed
                    ||issuer.taskObservationAdmissions!=1||!issuer.nativeSearchSamplingHistoryLocked(failed))
                throw new IllegalStateException("sampling successor original identity, drain, history or one-use deadline changed");
            session.requireBeforeFirstPlanning(now);
        }
        void requireOriginal(Object service,Object controller,NativeSearchSession expected,String task,File directory,long taskDeadline){
            if(service!=issuer||controller!=session.controller||session!=expected||!failed.taskId.equals(task)
                    ||directory!=failed.directory||session.taskDeadlineElapsed!=taskDeadline
                    ||!issuer.nativeSearchSessionCurrent(session,failed.scope)
                    ||issuer.activeObservation!=null||issuer.activeNativeSearchObservation!=null||issuer.capturePending
                    ||issuer.observationReadWorkPending()||issuer.actionWorkPending()||issuer.nativeCancellationWorkPending()
                    ||issuer.locked(session.background))
                throw new IllegalStateException("sampling successor current task or idle read ownership changed");
            session.background.requireAdmissionActive();
            synchronized(issuer.nativeSearchEventLock){requireLocked(SystemClock.elapsedRealtime());}
        }
        private void admit(NativeSearchRequest request){
            // Caller owns the event handoff lock; take the clock here, not before waiting for that lock.
            long now=SystemClock.elapsedRealtime();requireLocked(now);
            if(request.session!=session||request.scope!=failed.scope||request.directory!=failed.directory
                    ||request.started<drainedAt||request.started>now||request.id.equals(failed.id)
                    ||request.deadline>session.chainDeadlineElapsed||now>=request.deadline||request.cancel.isCancelled()
                    ||request.retrySubmission!=null||request.replanSubmission!=null
                    ||request.samplingSubmission!=this||issuer.ownedController!=session.controller||issuer.nativeSearchSession!=session
                    ||!consumed.compareAndSet(false,true))
                throw new IllegalStateException("sampling successor changed its new request or repeated admission");
            admitted=request;failed.samplingRecoveryPending=false;
        }
        private void requireSuccessor(NativeSearchRequest request){
            synchronized(issuer.nativeSearchEventLock){
                long now=SystemClock.elapsedRealtime();
                if(closed||!consumed.get()||admitted!=request||issuer.nativeSearchSamplingTracked!=failed
                        ||failed.samplingTrackingClosed||request.session!=session||request.scope!=failed.scope
                        ||request.directory!=failed.directory||request.started<drainedAt||now<request.started||now>=request.deadline
                        ||now>=session.chainDeadlineElapsed||!issuer.nativeSearchSamplingHistoryLocked(failed))
                    throw new IllegalStateException("sampling successor no longer owns its continuous inspection history");
                session.requireBeforeFirstPlanning(now);
            }
        }
        private void requireIdentity(NativeActionSnapshotCheck.Snapshot current){
            if(!failed.samplingAnchor.identity.equals(nativeSearchSamplingIdentity(current)))
                throw new IllegalStateException("new sampling read changed the historical owner/window identity");
        }
        void close(){issuer.closeNativeSearchSampling(failed);}
        Map<String,Object> evidence(){
            synchronized(issuer.nativeSearchEventLock){
                Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema","hepta.native-search-sampling-exhaustion-proof.v1");
                e.put("task_id",failed.taskId);e.put("failed_request_id",failed.id);e.put("session_binding",session.binding());
                e.put("reason","actual_local_sampling_fence");e.put("sampling_fence",failed.samplingExhaustion.fence);
                e.put("sampling_exhausted_elapsed_ms",failed.samplingExhaustion.observedElapsed);
                e.put("failed_request_started_elapsed_ms",failed.started);e.put("failed_request_deadline_elapsed_ms",failed.deadline);
                e.put("failed_request_terminal_elapsed_ms",failed.failureElapsed);e.put("read_queue_drain_observed_elapsed_ms",drainedAt);
                e.put("issued_elapsed_ms",issuedAt);e.put("original_task_deadline_elapsed_ms",session.taskDeadlineElapsed);
                e.put("original_chain_deadline_elapsed_ms",session.chainDeadlineElapsed);e.put("historical_owner_anchor",failed.samplingAnchor.evidence);
                e.put("failure_watermark",failed.failureWatermark.evidence());e.put("current_watermark",failed.events.mark().evidence());
                e.put("failed_diagnostic_leaf",failed.id+"-failed-native-search-planning.json");e.put("failed_diagnostic_sha256",failed.samplingDiagnosticSha);
                e.put("read_worker_drained",true);e.put("original_read_ordinal",1);e.put("successor_read_ordinal",2);
                e.put("old_request_renewed",false);e.put("old_census_reused",false);e.put("old_pair_accepted",false);
                e.put("model_requested",false);e.put("action_replayed",false);e.put("current_profile_authority",false);
                e.put("fresh_full_pair_required",true);e.put("grants_action_authority",false);e.put("business_verified",false);
                return NativeAppEvidence.immutableMap(e);
            }
        }
    }
    private boolean nativeSearchSamplingEligible(NativeSearchRequest request,long now){
        if(!request.callback.acceptsSamplingReadRetry()||request.samplingExhaustion==null||request.samplingExhaustion.request!=request
                ||request.samplingExhaustion.observedElapsed<request.started+10000
                ||request.samplingExhaustion.observedElapsed>=request.deadline
                ||request.samplingSubmission!=null||request.retrySubmission!=null||request.replanSubmission!=null
                ||request.samplingTrackingClosed||request.samplingDisqualified!=null||request.samplingAnchor==null
                ||!request.finished||!request.admitted||!request.workerDrained||request.published||request.path!=null
                ||request.lastCompletePair!=null||!request.failureDiagnosticClaimed||request.samplingDiagnosticSha==null
                ||request.diagnosticWritePending||request.samplingDrainUncertain||request.callbackDelivered.get()
                ||!"complete_pair_written".equals(request.diagnosticDisposition)
                ||taskObservationAdmissions!=1||!nativeSearchSessionCurrent(request.session,request.scope)
                ||request.cancel.isCancelled()||locked(request.session.background)||activeObservation!=null
                ||activeNativeSearchObservation!=null||capturePending||observationIoBusy.get()
                ||actionWorkPending()||nativeCancellationWorkPending()||now<request.failureElapsed
                ||now>=request.deadline||now>=request.session.chainDeadlineElapsed)return false;
        try{
            request.session.requireBeforeFirstPlanning(now);request.session.background.requireAdmissionActive();
            synchronized(nativeSearchEventLock){
                return nativeSearchSamplingTracked==request&&nativeSearchSamplingHistoryLocked(request);
            }
        }catch(RuntimeException refused){return false;}
    }
    private void watchNativeSearchSamplingHandoff(final NativeSearchRequest request){
        synchronized(nativeSearchEventLock){
            if(nativeSearchSamplingTracked!=request||!request.samplingRecoveryPending)return;
        }
        long now=SystemClock.elapsedRealtime();
        try{
            if(now<request.failureElapsed||now>=request.deadline||!nativeSearchSessionCurrent(request.session,request.scope))
                throw new IllegalStateException("unused sampling successor expired");
            request.session.requireBeforeFirstPlanning(now);
            if(!main.postDelayed(new Runnable(){public void run(){watchNativeSearchSamplingHandoff(request);}},
                    Math.max(1,Math.min(100,request.deadline-now))))closeNativeSearchSampling(request);
        }catch(RuntimeException unavailable){closeNativeSearchSampling(request);}
    }
    private boolean offerNativeSearchSamplingAfterDrain(final NativeSearchRequest request,final String detail){
        if(!nativeSearchSamplingEligible(request,SystemClock.elapsedRealtime())||!observationIoBusy.compareAndSet(false,true))return false;
        request.samplingRecoveryPending=true;
        // Expiry cleanup also covers an accepted but never delivered marker/main callback.
        watchNativeSearchSamplingHandoff(request);
        if(request.samplingTrackingClosed){observationIoBusy.set(false);return false;}
        try{observationIo.execute(new Runnable(){public void run(){
            // Actual serial marker, after the producer's finally and return; no Android or node reads.
            final long drained=SystemClock.elapsedRealtime();observationIoBusy.set(false);
            boolean posted=false;
            try{posted=main.post(new Runnable(){public void run(){
                NativeSearchSamplingExhaustionProof proof=null;
                try{
                    if(!nativeSearchSamplingEligible(request,SystemClock.elapsedRealtime()))
                        throw new IllegalStateException("sampling successor became unavailable after drain");
                    synchronized(nativeSearchEventLock){
                        long now=SystemClock.elapsedRealtime();
                        if(now<drained||drained<request.failureElapsed||now>=request.deadline
                                ||nativeSearchSamplingTracked!=request||!nativeSearchSamplingHistoryLocked(request))
                            throw new IllegalStateException("sampling successor drain or clock changed");
                        request.session.requireBeforeFirstPlanning(now);
                        proof=new NativeSearchSamplingExhaustionProof(HeptaAccessibilityService.this,request,drained,now);
                        request.samplingIssued=proof;
                    }
                    if(proof.closed)throw new IllegalStateException("sampling successor expiry watcher unavailable");
                    if(!request.callbackDelivered.compareAndSet(false,true)){proof.close();return;}
                    request.callback.onSamplingReadRetryAvailable(detail,proof);
                }catch(RuntimeException unavailable){
                    if(proof!=null)proof.close();else closeNativeSearchSampling(request);
                    deliverNativeSearchReadFailure(request,detail,null);
                }
            }});}finally{
                if(!posted){closeNativeSearchSampling(request);deliverNativeSearchReadFailure(request,detail,null);}
            }
        }});return true;}
        catch(java.util.concurrent.RejectedExecutionException rejected){observationIoBusy.set(false);closeNativeSearchSampling(request);return false;}
        catch(RuntimeException uncertain){
            // The queue may own work. Do not invent a drain or clear its busy flag.
            request.samplingDrainUncertain=true;closeNativeSearchSampling(request);return false;
        }
    }
    private void throwNativeSearchSamplingExhausted(NativeSearchRequest request,String fence){
        requireNativeSearchRead(request);
        long now=SystemClock.elapsedRealtime();
        if(now<request.started||now-request.started<10000||now>=request.deadline)throw new ObservationAbandoned();
        if("complete_pair".equals(fence))request.lastSampleRejection="规划双读超过原10秒采样界限";
        throw new NativeSearchSamplingExhausted(request,now,fence);
    }

    /** One successor read, never an observation or action capability. The
     * issuer can create it only after the failed initial worker and private
     * diagnostic have returned through the same serial queue. */
    static final class NativeSearchReadRetryProof {
        private final HeptaAccessibilityService issuer;
        private final NativeSearchRequest failed;
        private final NativeSearchSession session;
        private final long drainedAt;
        private final Map<String,Object> identity,classification;
        private final java.util.concurrent.atomic.AtomicBoolean consumed=new java.util.concurrent.atomic.AtomicBoolean();
        private NativeSearchReadRetryProof(HeptaAccessibilityService issuer,NativeSearchRequest failed,long drainedAt){
            this.issuer=issuer;this.failed=failed;session=failed.session;this.drainedAt=drainedAt;
            identity=failed.loadingRetryIdentity;classification=failed.loadingRetryClassification;
        }
        void requireOriginal(Object service,Object controller,NativeSearchSession expected,String task,File directory,long taskDeadline){
            if(service!=issuer||session!=expected||session.controller!=controller||!failed.taskId.equals(task)
                    ||failed.directory!=directory||session.taskDeadlineElapsed!=taskDeadline||consumed.get()
                    ||failed.retrySubmission!=null||!failed.finished||!failed.workerDrained||failed.published
                    ||issuer.nativeSearchRetryPending!=failed)
                throw new IllegalStateException("initial planning read recovery task or one-use binding changed");
            NativeSearchPlanning.EventMark events=failed.events.mark();
            if(events.unknown!=0||events.boundary!=0||events.events!=events.content||!events.monotonicSince(failed.failureWatermark))
                throw new IllegalStateException("initial planning recovery encountered unknown or ownership-boundary events");
        }
        private void requireIdentity(NativeActionSnapshotCheck.Snapshot snapshot){
            Map<String,Object> current=new java.util.TreeMap<String,Object>(NativeSearchRole.stableEnvelope(snapshot));
            current.remove("origin_observation_id");
            if(!identity.equals(current))throw new IllegalStateException("initial planning successor window/ownership identity changed");
        }
        Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema","hepta.native-search-initial-read-retry-proof.v1");
            out.put("task_id",failed.taskId);out.put("failed_request_id",failed.id);out.put("session_binding",session.binding());
            out.put("original_task_deadline_elapsed_ms",session.taskDeadlineElapsed);
            out.put("failed_request_started_elapsed_ms",failed.started);out.put("failed_request_deadline_elapsed_ms",failed.deadline);
            out.put("failed_request_terminal_elapsed_ms",failed.failureElapsed);out.put("read_queue_drain_observed_elapsed_ms",drainedAt);
            out.put("failed_request_terminal_status","failed");out.put("reason",classification);
            out.put("failed_request_diagnostic_leaf",failed.id+"-failed-native-search-planning.json");
            out.put("diagnostic_disposition",failed.diagnosticDisposition);out.put("failure_watermark",failed.failureWatermark.evidence());
            out.put("read_worker_drained",true);out.put("original_read_ordinal",1);out.put("successor_read_ordinal",2);
            out.put("previous_pair_accepted",false);out.put("old_request_renewed",false);out.put("old_census_reused",false);
            out.put("model_requested",false);out.put("action_replayed",false);out.put("fresh_full_pair_required",true);
            out.put("grants_action_authority",false);out.put("business_verified",false);return NativeAppEvidence.immutableMap(out);
        }
    }

    /** A capability for one fresh full read, never a second use of an intent.
     * Only this Service creates it after the real worker/queue marker and its
     * original current main callback. JSON evidence cannot construct one. */
    static final class NativeSearchNoEffectReplanProof {
        private final HeptaAccessibilityService issuer;
        private final SearchActionWork work;
        private final ActionOutcome outcome;
        private final File directory;
        private final long issuedElapsed;
        private final Map<String,Object> facts;
        private final java.util.concurrent.atomic.AtomicBoolean consumed=new java.util.concurrent.atomic.AtomicBoolean();
        private volatile NativeSearchRequest admittedRequest;
        private NativeSearchNoEffectReplanProof(HeptaAccessibilityService issuer,SearchActionWork work,ActionOutcome outcome,long now){
            this.issuer=issuer;this.work=work;this.outcome=outcome;directory=work.planningDirectory;issuedElapsed=now;
            Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema","hepta.native-search-no-effect-replan-proof.v1");
            e.put("task_id",work.session.taskId);e.put("operation_id",work.state.operationId);
            e.put("model_run_id",work.attempt.modelRunId);e.put("old_observation_id",work.attempt.offer.planning.id);
            e.put("old_planning_receipt_sha256",work.attempt.offer.planning.receiptSha256);e.put("session_binding",work.session.binding());
            e.put("original_task_deadline_elapsed_ms",work.session.taskDeadlineElapsed);
            e.put("chain_started_elapsed_ms",work.session.startedElapsed);e.put("chain_deadline_elapsed_ms",work.session.chainDeadlineElapsed);
            e.put("old_attempt_started_elapsed_ms",work.attempt.startedElapsed);e.put("old_attempt_deadline_elapsed_ms",work.attempt.deadlineElapsed);
            e.put("original_read_ordinal",work.planningReadOrdinal);e.put("successor_read_ordinal",work.planningReadOrdinal+1);
            e.put("replan_ordinal",1);e.put("rejection_reason",work.noEffectRejectionReason());
            e.put("first_final_event_check_elapsed_ms",work.firstFinalEventsElapsed<0?null:Long.valueOf(work.firstFinalEventsElapsed));
            e.put("after_target_refresh_event_check_elapsed_ms",work.afterTargetRefreshEventsElapsed<0?null:Long.valueOf(work.afterTargetRefreshEventsElapsed));
            e.put("rejection_watermark",work.noEffectRejectionWatermark().evidence());e.put("D_completed_watermark",work.pairCompleted.evidence());
            e.put("action_queue_drain_marker_elapsed_ms",work.replanDrainMarkerElapsed);e.put("issued_elapsed_ms",now);
            e.put("publication_watermark",work.events.mark().evidence());e.put("worker_drained",true);e.put("guard_claimed",false);
            e.put("platform_call_invoked",false);e.put("effect_entered",false);e.put("callback_authority_current",true);
            e.put("sealed_diagnostic_sha256",work.sealedDiagnosticSha);
            e.put("fresh_full_pair_and_new_model_required",true);e.put("old_attempt_renewed",false);
            e.put("automatic_redispatch",false);e.put("grants_action_authority",false);e.put("business_verified",false);
            facts=NativeAppEvidence.immutableMap(e);
        }
        void requireOutcome(ActionOutcome actual){
            if(actual!=outcome)throw new IllegalStateException("no-effect proof is not this actual callback outcome");
        }
        void requireOriginal(NativeSearchSession session,NativeSearchSession.Attempt attempt,long now,boolean closed){
            long sampled=SystemClock.elapsedRealtime();
            if(sampled<now)throw new IllegalStateException("no-effect proof clock moved backwards");
            now=sampled; // Journal/fsync time cannot reuse a caller's earlier deadline sample.
            if(session!=work.session||attempt!=work.attempt||issuer!=live||directory==null
                    ||issuer.nativeSearchPlanningDirectory!=directory||consumed.get()||now<issuedElapsed
                    ||now>=work.attempt.deadlineElapsed||now>=session.chainDeadlineElapsed
                    ||!issuer.nativeSearchSessionCurrent(session,work.scope)||issuer.lastActionExecution!=work.state
                    ||issuer.activeSearchAction!=null||issuer.activeObservation!=null||issuer.activeNativeSearchObservation!=null
                    ||issuer.capturePending||issuer.observationReadWorkPending()||issuer.actionWorkPending()
                    ||issuer.nativeCancellationWorkPending()||work.cancel.isCancelled()
                    ||issuer.taskObservationAdmissions!=work.planningReadOrdinal)
                throw new IllegalStateException("no-effect search successor lost its original task/drain/read boundary");
            session.requireLive(now);
            if(closed)attempt.requireClosedForSuccessor();else session.requireNoEffectCandidate(attempt,now);
            issuer.requireNativeSearchNoEffectFacts(work,outcome);
            synchronized(issuer.nativeSearchEventLock){
                if(issuer.nativeSearchTrackedAction!=work)throw new IllegalStateException("search event tracker was superseded");
                requireNativeSearchPairEvents(work.pairCompleted,work.events.mark());
                if(!work.events.mark().monotonicSince(work.noEffectRejectionWatermark()))
                    throw new IllegalStateException("search rejection watermark moved backwards");
            }
        }
        void requireReadTarget(Object service,Object controller,NativeSearchSession session,String task,File directory,long taskDeadline){
            if(service!=issuer||session!=work.session||controller!=session.controller||!session.taskId.equals(task)
                    ||this.directory!=directory||session.taskDeadlineElapsed!=taskDeadline)
                throw new IllegalStateException("no-effect successor read target changed");
            requireOriginal(session,work.attempt,SystemClock.elapsedRealtime(),true);
        }
        /** Caller holds the event-routing lock; no Android/file work here. */
        private void admit(NativeSearchRequest request){
            long now=SystemClock.elapsedRealtime();
            if(now<issuedElapsed||now>=work.attempt.deadlineElapsed||now>=work.session.chainDeadlineElapsed)
                throw new IllegalStateException("no-effect successor admission reached its unchanged original deadline");
            if(issuer.nativeSearchTrackedAction!=work||request.session!=work.session||request.scope!=work.scope
                    ||request.directory!=directory||request.started<work.replanDrainMarkerElapsed
                    ||request.deadline>work.session.chainDeadlineElapsed||request.id.equals(work.attempt.offer.planning.id)
                    ||issuer.taskObservationAdmissions!=work.planningReadOrdinal||work.cancel.isCancelled())
                throw new IllegalStateException("new search planning admission differs from the closed old work");
            requireNativeSearchPairEvents(work.pairCompleted,work.events.mark());
            if(!work.events.mark().monotonicSince(work.noEffectRejectionWatermark())||!consumed.compareAndSet(false,true))
                throw new IllegalStateException("no-effect successor read already consumed or event clock changed");
            request.events.window=work.state.windowId;
            admittedRequest=request;
        }
        void requirePublishedPlanning(NativeSearchSession session,NativeSearchPlanning planning){
            NativeSearchRequest request=admittedRequest;
            if(!consumed.get()||request==null||request.session!=session||session!=work.session
                    ||!request.finished||!request.published||!request.workerDrained||request.publishedPlanning!=planning
                    ||planning==null||!request.id.equals(planning.id)||planning.timing.requestStarted!=request.started
                    ||planning.timing.requestStarted<work.replanDrainMarkerElapsed||planning.timing.requestDeadline!=request.deadline)
                throw new IllegalStateException("fresh search Offer did not come from this actual successor read");
        }
        private void requireFreshIdentity(NativeActionSnapshotCheck.Snapshot snapshot){
            Map<String,Object> original=new java.util.TreeMap<String,Object>(NativeSearchRole.stableEnvelope(work.latestSnapshot));
            Map<String,Object> current=new java.util.TreeMap<String,Object>(NativeSearchRole.stableEnvelope(snapshot));
            original.remove("origin_observation_id");current.remove("origin_observation_id");
            if(!original.equals(current))throw new IllegalStateException("fresh search planning crossed the old window/ownership boundary");
        }
        Map<String,Object> evidence(){return facts;}
    }

    private static final class NativeSearchLoadingTransition extends IllegalStateException {
        private static final long serialVersionUID=1L;
        NativeSearchLoadingTransition(){super("complete loading shell became search home; this pair is not a planning observation");}
    }
    private static final class NativeSearchRequest {
        final NativeSearchSession session;final QualificationScopeConfig.Bound scope;final String taskId,id;
        final File directory;final Cancellation cancel;final NativeSearchSession.ObservationCallback callback;
        final long started,deadline;final SearchEvents events;
        final java.util.concurrent.atomic.AtomicBoolean callbackDelivered=new java.util.concurrent.atomic.AtomicBoolean();
        NativeSearchReadRetryProof retrySubmission;
        NativeSearchNoEffectReplanProof replanSubmission;
        NativeSearchSamplingExhaustionProof samplingSubmission;
        volatile NativeSearchSamplingExhausted samplingExhaustion;
        volatile NativeSearchSamplingAnchor samplingAnchor;
        volatile NativeSearchSamplingExhaustionProof samplingIssued;
        volatile NativeSearchPlanning.EventMark samplingLastVerified;
        volatile String samplingDisqualified,samplingDiagnosticSha;
        volatile boolean samplingTrackingClosed,samplingRecoveryPending,samplingDrainUncertain;
        volatile NativeSearchPlanning publishedPlanning;
        volatile Map<String,Object> loadingRetryClassification,loadingRetryIdentity;
        volatile boolean retryDrainPending,retryDrainUncertain;
        volatile boolean finished,workerDrained,published,admitted;volatile String phase="queued";
        volatile File path;
        volatile NativeSearchPair lastCompletePair;
        volatile String lastSampleRejection;
        volatile boolean diagnosticWritePending,diagnosticWriteDrained;
        volatile String diagnosticDisposition="not_requested";
        boolean failureDiagnosticClaimed;String failureReason,failurePhase;long failureElapsed=-1;
        NativeSearchPlanning.EventMark failureWatermark;
        NativeSearchRequest(String taskId,File directory,NativeSearchSession session,QualificationScopeConfig.Bound scope,
                Cancellation cancel,long deadline,NativeSearchSession.ObservationCallback callback){
            this.taskId=taskId;this.directory=directory;this.session=session;this.scope=scope;this.cancel=cancel;
            this.deadline=deadline;this.callback=callback;started=SystemClock.elapsedRealtime();
            id=UUID.randomUUID().toString().replace("-","");events=new SearchEvents(session.background.displayId(),session.goal.packageName);
        }
    }
    private static final class NativeSearchSample {
        final NativeActionSnapshotCheck.Snapshot snapshot;final Map<String,Object> windows;
        final WindowOwnership profile;final long readStarted,readCompleted,captured;
        final NativeSearchPlanning.EventMark before,after;
        NativeSearchSample(Graph graph,NativeActionSnapshotCheck.Snapshot snapshot,Map<String,Object> windows,
                NativeSearchPlanning.EventMark before,NativeSearchPlanning.EventMark after){
            this.snapshot=snapshot;this.windows=windows;profile=graph.profileWindow;
            readStarted=graph.readStartedElapsedMs;readCompleted=graph.readCompletedElapsedMs;captured=graph.nativeActionCapturedAt;
            this.before=before;this.after=after;
        }
    }
    private static final class NativeSearchPair {
        final NativeSearchSample first,second;
        NativeSearchPair(NativeSearchSample first,NativeSearchSample second){this.first=first;this.second=second;}
    }
    void observeNativeSearchPlanning(final String taskId,final File directory,final NativeSearchSession session,
            final Cancellation cancel,final long deadline,final NativeSearchSession.ObservationCallback callback){
        if(session==null||cancel==null||callback==null||directory==null||!taskId.equals(session.taskId))
            throw new IllegalArgumentException("actual search request/Session/callback required");
        observeNativeSearchPlanning(taskId,directory,session,cancel,deadline,callback,null);
    }
    void observeNativeSearchPlanning(final String taskId,final File directory,final NativeSearchSession session,
            final Cancellation cancel,final long deadline,final NativeSearchSession.ObservationCallback callback,
            final NativeSearchReadRetryProof proof){
        observeNativeSearchPlanningInternal(taskId,directory,session,cancel,deadline,callback,proof,null,null);
    }
    void observeNativeSearchPlanningAfterNoEffect(final String taskId,final File directory,final NativeSearchSession session,
            final Cancellation cancel,final long deadline,final NativeSearchSession.ObservationCallback callback,
            final NativeSearchNoEffectReplanProof proof){
        if(proof==null)throw new IllegalArgumentException("actual no-effect planning successor proof required");
        observeNativeSearchPlanningInternal(taskId,directory,session,cancel,deadline,callback,null,proof,null);
    }
    void observeNativeSearchPlanningAfterSamplingExhaustion(final String taskId,final File directory,final NativeSearchSession session,
            final Cancellation cancel,final long deadline,final NativeSearchSession.ObservationCallback callback,
            final NativeSearchSamplingExhaustionProof proof){
        if(proof==null)throw new IllegalArgumentException("actual sampling exhaustion proof required");
        observeNativeSearchPlanningInternal(taskId,directory,session,cancel,deadline,callback,null,null,proof);
    }
    private void observeNativeSearchPlanningInternal(final String taskId,final File directory,final NativeSearchSession session,
            final Cancellation cancel,final long deadline,final NativeSearchSession.ObservationCallback callback,
            final NativeSearchReadRetryProof proof,final NativeSearchNoEffectReplanProof replan,
            final NativeSearchSamplingExhaustionProof sampling){
        if(session==null||cancel==null||callback==null||directory==null||!taskId.equals(session.taskId))
            throw new IllegalArgumentException("actual search request/Session/callback required");
        final NativeSearchRequest request=new NativeSearchRequest(taskId,directory,session,scopeFor(taskId),cancel,deadline,callback);
        request.retrySubmission=proof;request.replanSubmission=replan;request.samplingSubmission=sampling;
        boolean posted=main.post(new Runnable(){public void run(){
            try{
                long now=SystemClock.elapsedRealtime();
                if(!nativeSearchSessionCurrent(session,request.scope)
                        ||activeObservation!=null||activeNativeSearchObservation!=null||capturePending
                        ||observationReadWorkPending()||actionWorkPending()||nativeCancellationWorkPending()
                        ||cancel.isCancelled()||locked(session.background)||now<request.started||now>=deadline
                        ||deadline>session.chainDeadlineElapsed
                        ||deadline>ObservationStabilityGate.requestDeadline(request.started,session.chainDeadlineElapsed))
                    throw new IllegalStateException("native planning request admission is no longer current");
                if(replan==null){
                    if(proof!=null&&sampling!=null)throw new IllegalStateException("initial recovery proof kinds are exclusive");
                    boolean initialSuccessor=proof!=null||sampling!=null;
                    if(nativeSearchPlanningAdmitted!=initialSuccessor||taskObservationAdmissions!=(initialSuccessor?1:0))
                        throw new IllegalStateException("original initial planning admission ordinal changed");
                    session.requireBeforeFirstPlanning(now);
                    if(proof!=null){
                        proof.requireOriginal(HeptaAccessibilityService.this,ownedController,session,taskId,directory,session.taskDeadlineElapsed);
                        if(proof.failed.scope!=request.scope||request.started<proof.drainedAt||!proof.consumed.compareAndSet(false,true))
                            throw new IllegalStateException("initial planning successor drain or one-use boundary changed");
                        nativeSearchRetryPending=null;
                    }else if(nativeSearchRetryPending!=null)throw new IllegalStateException("unconsumed loading read recovery exists");
                    if(sampling!=null)sampling.requireOriginal(HeptaAccessibilityService.this,ownedController,session,taskId,directory,session.taskDeadlineElapsed);
                    synchronized(nativeSearchEventLock){
                        if(nativeSearchTrackedAction!=null)throw new IllegalStateException("search action tracker cannot enter initial planning");
                        if(nativeSearchPlanningDirectory==null)nativeSearchPlanningDirectory=directory;
                        if(nativeSearchPlanningDirectory!=directory)throw new IllegalStateException("search evidence directory changed");
                        if(sampling!=null)sampling.admit(request);
                        else{
                            if(nativeSearchSamplingTracked!=null)throw new IllegalStateException("previous sampling tracker still owns initial admission");
                            if(proof==null)nativeSearchSamplingTracked=request;
                        }
                        activeNativeSearchObservation=request;
                    }
                }else{
                    if(!nativeSearchPlanningAdmitted||proof!=null||sampling!=null||nativeSearchRetryPending!=null||nativeSearchSamplingTracked!=null)
                        throw new IllegalStateException("no-effect planning successor crossed an initial read recovery");
                    session.requireFreshPlanningAfterNoEffect(replan,now);
                    replan.requireReadTarget(HeptaAccessibilityService.this,ownedController,session,taskId,directory,session.taskDeadlineElapsed);
                    synchronized(nativeSearchEventLock){
                        replan.admit(request);
                        // Callback routing observes old tracker or new request, never an empty interval.
                        activeNativeSearchObservation=request;nativeSearchTrackedAction=null;
                    }
                }
                nativeSearchPlanningAdmitted=true;taskObservationAdmissions++;request.admitted=true;
                watchNativeSearchObservation(request);if(request.finished)return;
                if(!observationIoBusy.compareAndSet(false,true))throw new IllegalStateException("previous read worker still owns capacity");
                try{observationIo.execute(new Runnable(){public void run(){produceNativeSearchPlanning(request);}});}
                catch(java.util.concurrent.RejectedExecutionException rejected){
                    request.workerDrained=true;observationIoBusy.set(false);finishNativeSearchObservation(request,null,"规划读取队列未接受请求");
                }catch(RuntimeException uncertain){
                    // An uncertain submit never proves that a read worker has drained.
                    finishNativeSearchObservation(request,null,"规划读取队列状态不明；不重复提交");
                }
            }catch(Exception refused){finishNativeSearchObservation(request,null,"规划观察未启动："+message(refused));}
        }});
        if(!posted)finishNativeSearchObservation(request,null,"规划观察主线程没有接受请求");
    }
    private void requireNativeSearchRead(NativeSearchRequest request){
        long now=SystemClock.elapsedRealtime();
        if(request.finished||activeNativeSearchObservation!=request||request.cancel.isCancelled()
                ||!nativeSearchSessionCurrent(request.session,request.scope)||now<request.started||now>=request.deadline)
            throw new ObservationAbandoned();
        request.session.requireLive(now);
        if(request.samplingSubmission!=null)request.samplingSubmission.requireSuccessor(request);
        if(request.replanSubmission!=null)
            requireNativeSearchPairEvents(new NativeSearchPlanning.EventMark(0,0,0,0),request.events.mark());
    }
    private GraphBudget nativeSearchReadBudget(final NativeSearchRequest request){
        return new GraphBudget(){public void check(){requireNativeSearchRead(request);}
            public Cancellation cancellation(){return request.cancel;}public long deadline(){return request.deadline;}};
    }
    private void watchNativeSearchObservation(final NativeSearchRequest request){
        if(request.finished)return;
        try{requireNativeSearchRead(request);if(locked(request.session.background))throw new ObservationAbandoned();}
        catch(RuntimeException retired){finishNativeSearchObservation(request,null,"规划观察已停止或到期 [phase="+request.phase+"]");return;}
        if(!main.postDelayed(new Runnable(){public void run(){watchNativeSearchObservation(request);}},
                Math.max(1,Math.min(100,request.deadline-SystemClock.elapsedRealtime()))))
            finishNativeSearchObservation(request,null,"规划观察看护已停止");
    }
    private void finishNativeSearchObservation(NativeSearchRequest request,NativeSearchPlanning value,String error){
        final boolean diagnostic;
        synchronized(nativeSearchEventLock){
            // Last sampling-successor history check and publication state change are one handoff.
            // No I/O or callback is performed while this lock is held.
            if(value!=null&&request.samplingSubmission!=null){
                try{request.samplingSubmission.requireSuccessor(request);}
                catch(RuntimeException refused){value=null;error="sampling successor publication refused: "+message(refused);}
            }
            synchronized(request){
                if(request.finished)return;
                if(value==null)recordNativeSearchFailure(request,error);
                request.publishedPlanning=value;request.finished=true;request.published=value!=null;
                diagnostic=value==null&&request.admitted&&request.workerDrained&&!request.failureDiagnosticClaimed;
                if(value!=null)request.lastCompletePair=null;
            }
            if(value!=null&&request.samplingSubmission!=null)closeNativeSearchSampling(request);
        }
        // A publication rejection can occur after the read worker really drained.
        // Its successor owns only a bounded private diagnostic write, never a new read.
        if(diagnostic)queueNativeSearchFailureDiagnostic(request);
        synchronized(this){if(activeNativeSearchObservation==request)activeNativeSearchObservation=null;}
        if(value==null&&request.workerDrained&&request.path!=null)request.path.delete();
        if(value==null){
            final String detail=error+" [diagnostic="+request.diagnosticDisposition+"]";
            if(offerNativeSearchSamplingAfterDrain(request,detail))return;
            boolean loading=offerNativeSearchLoadingRetryAfterDrain(request,detail);
            closeNativeSearchSampling(request);
            if(!loading)deliverNativeSearchReadFailure(request,detail,null);
        }else{
            closeNativeSearchSampling(request);
            if(request.callbackDelivered.compareAndSet(false,true))request.callback.onPlanning(value);
        }
    }
    private static void deliverNativeSearchReadFailure(NativeSearchRequest request,String detail,NativeSearchReadRetryProof proof){
        if(!request.callbackDelivered.compareAndSet(false,true))return;
        if(proof==null)request.callback.onError(detail);else request.callback.onLoadingReadRetryAvailable(detail,proof);
    }
    private boolean nativeSearchLoadingRetryEligible(NativeSearchRequest request,long now){
        if((nativeSearchRetryPending!=null&&nativeSearchRetryPending!=request)
                ||request.retrySubmission!=null||request.replanSubmission!=null||request.samplingSubmission!=null||request.loadingRetryClassification==null||request.loadingRetryIdentity==null
                ||!request.finished||!request.admitted||!request.workerDrained||request.published||request.path!=null
                ||!request.failureDiagnosticClaimed||request.diagnosticWritePending||request.retryDrainPending||request.retryDrainUncertain
                ||!"complete_pair_written".equals(request.diagnosticDisposition)||request.callbackDelivered.get()
                ||taskObservationAdmissions!=1||!nativeSearchSessionCurrent(request.session,request.scope)
                ||request.cancel.isCancelled()||locked(request.session.background)||activeObservation!=null
                ||activeNativeSearchObservation!=null||capturePending||observationIoBusy.get()
                ||actionWorkPending()||nativeCancellationWorkPending()||request.failureElapsed<request.started
                ||now<request.failureElapsed||now>=request.deadline||now>=request.session.taskDeadlineElapsed)return false;
        NativeSearchPlanning.EventMark events=request.events.mark();
        if(events.unknown!=0||events.boundary!=0||events.events!=events.content
                ||request.failureWatermark==null||!events.monotonicSince(request.failureWatermark))return false;
        try{request.session.requireBeforeFirstPlanning(now);return true;}catch(RuntimeException unavailable){return false;}
    }
    private boolean offerNativeSearchLoadingRetryAfterDrain(final NativeSearchRequest request,final String detail){
        if(!nativeSearchLoadingRetryEligible(request,SystemClock.elapsedRealtime())||!observationIoBusy.compareAndSet(false,true))return false;
        nativeSearchRetryPending=request;request.retryDrainPending=true;
        try{observationIo.execute(new Runnable(){public void run(){
            // This marker runs after the actual original producer returned.
            // It reads no nodes, renews no request, and owns only queue capacity.
            final long drainedAt=SystemClock.elapsedRealtime();request.retryDrainPending=false;observationIoBusy.set(false);
            boolean posted=main.post(new Runnable(){public void run(){
                long now=SystemClock.elapsedRealtime();
                if(nativeSearchRetryPending!=request||drainedAt<request.failureElapsed||now<drainedAt||!nativeSearchLoadingRetryEligible(request,now)){
                    deliverNativeSearchReadFailure(request,detail,null);return;
                }
                deliverNativeSearchReadFailure(request,detail,new NativeSearchReadRetryProof(HeptaAccessibilityService.this,request,drainedAt));
            }});
            if(!posted)deliverNativeSearchReadFailure(request,detail,null);
        }});return true;}
        catch(java.util.concurrent.RejectedExecutionException rejected){request.retryDrainPending=false;observationIoBusy.set(false);
            if(nativeSearchRetryPending==request)nativeSearchRetryPending=null;return false;}
        catch(RuntimeException uncertain){request.retryDrainUncertain=true;return false;}
    }
    private static void recordNativeSearchFailure(NativeSearchRequest request,String reason){
        synchronized(request){if(request.failureReason!=null)return;
            request.failureReason=reason==null?"planning request failed without a detail":reason;
            request.failurePhase=request.phase;request.failureElapsed=SystemClock.elapsedRealtime();request.failureWatermark=request.events.mark();}
    }
    private void queueNativeSearchFailureDiagnostic(final NativeSearchRequest request){
        if(!observationIoBusy.compareAndSet(false,true)){request.diagnosticDisposition="unavailable_capacity";return;}
        synchronized(request){request.diagnosticWritePending=true;request.diagnosticWriteDrained=false;request.diagnosticDisposition="writer_queued";}
        try{observationIo.execute(new Runnable(){public void run(){
            try{
                synchronized(request){request.failureDiagnosticClaimed=true;}
                writeNativeSearchFailureDiagnostic(request);
                if(request.path!=null&&!request.published)request.path.delete();
            }finally{synchronized(request){request.diagnosticWriteDrained=true;request.diagnosticWritePending=false;observationIoBusy.set(false);}}
        }});}
        catch(java.util.concurrent.RejectedExecutionException rejected){
            synchronized(request){request.failureDiagnosticClaimed=true;request.diagnosticDisposition="unavailable_queue_rejected";
                request.diagnosticWriteDrained=true;request.diagnosticWritePending=false;observationIoBusy.set(false);}
        }catch(RuntimeException uncertain){
            request.diagnosticDisposition="writer_submission_uncertain";
            // As with the read submit, an uncertain executor return proves no drain.
        }
    }
    private void drainNativeSearchRead(NativeSearchRequest request){
        for(;;){
            synchronized(request){
                if(request.failureReason==null||request.failureDiagnosticClaimed){request.workerDrained=true;observationIoBusy.set(false);return;}
                request.failureDiagnosticClaimed=true;
            }
            writeNativeSearchFailureDiagnostic(request);
        }
    }
    private static Map<String,Object> nativeSearchDiagnosticSample(NativeSearchSample sample){
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("census",NativeSearchPlanning.snapshot(sample.snapshot));
        out.put("windows",sample.windows);out.put("read_started_elapsed_ms",sample.readStarted);
        out.put("read_completed_elapsed_ms",sample.readCompleted);out.put("census_captured_elapsed_ms",sample.captured);
        out.put("before_watermark",sample.before.evidence());out.put("after_watermark",sample.after.evidence());return out;
    }
    /** Existing immutable reads only. No sample, authority, deadline extension or successful outcome is created. */
    private static void writeNativeSearchFailureDiagnostic(NativeSearchRequest request){
        try{
            if(!request.directory.isDirectory()){request.diagnosticDisposition="unavailable_private_directory";return;}
            NativeSearchPair pair=request.lastCompletePair;
            Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema","hepta.failed-native-search-planning.v1");
            out.put("task_id",request.taskId);out.put("request_id",request.id);out.put("session_binding",request.session.binding());
            out.put("request_started_elapsed_ms",request.started);out.put("request_deadline_elapsed_ms",request.deadline);
            out.put("sampling_deadline_elapsed_ms",Math.min(request.deadline,request.started+10000));
            out.put("failed_elapsed_ms",request.failureElapsed);out.put("failure_phase",request.failurePhase);
            out.put("diagnostic_writer_kind",request.workerDrained?"post_read_diagnostic_worker":"original_read_worker");
            out.put("read_worker_drained_before_write",request.workerDrained);
            out.put("diagnostic_successor_pending_at_write",request.diagnosticWritePending);
            String reason=request.failureReason;out.put("failure_reason",reason.length()<=4096?reason:reason.substring(0,4096));
            String last=request.lastSampleRejection;out.put("last_sample_rejection",last==null?null:last.length()<=4096?last:last.substring(0,4096));
            out.put("failure_watermark",request.failureWatermark==null?null:request.failureWatermark.evidence());
            out.put("complete_pair_available",pair!=null);out.put("pair_omitted_for_budget",false);
            Map<String,Object> both=null;if(pair!=null){both=new LinkedHashMap<String,Object>();
                both.put("first",nativeSearchDiagnosticSample(pair.first));both.put("second",nativeSearchDiagnosticSample(pair.second));}
            out.put("last_complete_pair",both);out.put("diagnostic_only",true);out.put("planning_published",false);
            out.put("new_samples_taken_for_diagnostic",0);out.put("action_permission",false);
            if(request.samplingExhaustion!=null){
                Map<String,Object> sampling=new LinkedHashMap<String,Object>();
                sampling.put("reason","actual_local_sampling_fence");sampling.put("fence",request.samplingExhaustion.fence);
                sampling.put("observed_elapsed_ms",request.samplingExhaustion.observedElapsed);
                sampling.put("historical_owner_anchor",request.samplingAnchor==null?null:request.samplingAnchor.evidence);
                sampling.put("ineligible_reason",request.samplingDisqualified);
                sampling.put("current_profile_authority",false);sampling.put("old_pair_accepted",false);
                out.put("sampling_exhaustion",sampling);
            }
            byte[] raw=NativeSearchPlanning.json(out).toString().getBytes(StandardCharsets.UTF_8);
            if(raw.length>NativeSearchPlanning.MAX_BYTES){out.put("last_complete_pair",null);out.put("pair_omitted_for_budget",pair!=null);
                raw=NativeSearchPlanning.json(out).toString().getBytes(StandardCharsets.UTF_8);}
            if(raw.length>NativeSearchPlanning.MAX_BYTES){request.diagnosticDisposition="unavailable_metadata_budget";return;}
            File diagnosticPath=new File(request.directory,request.id+"-failed-native-search-planning.json");
            MobiMindPrivateFiles.writeNew(diagnosticPath,raw);
            if(request.samplingExhaustion!=null){
                MobiMindPrivateFiles.Read saved=MobiMindPrivateFiles.read(diagnosticPath,NativeSearchPlanning.MAX_BYTES,true);
                if(!java.util.Arrays.equals(raw,saved.bytes))throw new IllegalStateException("sampling failure diagnostic readback differs");
                saved.unchangedPath();request.samplingDiagnosticSha=sha(saved.bytes);
            }
            request.diagnosticDisposition=pair!=null&&both!=null&&Boolean.FALSE.equals(out.get("pair_omitted_for_budget"))?"complete_pair_written":"metadata_written";
        }catch(Exception unavailable){request.diagnosticDisposition="unavailable_write_failed";/* No successful outcome or retry permission. */}
        finally{request.lastCompletePair=null;}
    }
    private void retireNativeSearch(String taskId,String reason){
        synchronized(nativeSearchEventLock){
            if(nativeSearchSamplingTracked!=null&&nativeSearchSamplingTracked.taskId.equals(taskId))
                closeNativeSearchSampling(nativeSearchSamplingTracked);
        }
        NativeSearchRequest retry=nativeSearchRetryPending;
        if(retry!=null&&retry.taskId.equals(taskId))nativeSearchRetryPending=null;
        NativeSearchSession session=nativeSearchSession;
        if(session!=null&&session.taskId.equals(taskId))session.retire();
        NativeSearchRequest request=activeNativeSearchObservation;
        if(request!=null&&request.taskId.equals(taskId))finishNativeSearchObservation(request,null,"规划观察已退休："+reason);
        SearchActionWork work=activeSearchAction;
        if(work!=null&&work.state.taskId.equals(taskId))work.state.retire(reason);
        synchronized(nativeSearchEventLock){
            if(nativeSearchTrackedAction!=null&&nativeSearchTrackedAction.session.taskId.equals(taskId))nativeSearchTrackedAction=null;
        }
    }
    private void waitNativeSearchSample(NativeSearchRequest request,long until){
        while(SystemClock.elapsedRealtime()<until){requireNativeSearchRead(request);
            if(SystemClock.elapsedRealtime()>=Math.min(request.deadline,request.started+10000))
                throwNativeSearchSamplingExhausted(request,"sample_wait");
            SystemClock.sleep(Math.min(50,Math.max(1,until-SystemClock.elapsedRealtime())));
        }
        requireNativeSearchRead(request);
    }
    private NativeSearchSample readNativeSearchSample(NativeSearchRequest request){
        Graph graph=null;NativeSearchPlanning.EventMark before=request.events.mark();
        try{
            graph=readGraph(nativeSearchReadBudget(request),request.session.background);requireNativeSearchRead(request);
            NativeActionSnapshotCheck.Snapshot snapshot=nativeSearchSnapshot(graph,request.session,request.id,request.started);
            if(request.samplingSubmission!=null)request.samplingSubmission.requireIdentity(snapshot);
            synchronized(nativeSearchEventLock){
                if(nativeSearchSamplingTracked==request&&request.samplingAnchor!=null
                        &&!request.samplingAnchor.identity.equals(nativeSearchSamplingIdentity(snapshot)))
                    disqualifyNativeSearchSampling(request,"later complete census changed historical owner/window");
            }
            if(request.retrySubmission!=null)request.retrySubmission.requireIdentity(snapshot);
            if(request.replanSubmission!=null)request.replanSubmission.requireFreshIdentity(snapshot);
            request.events.window=graph.windowId;
            return new NativeSearchSample(graph,snapshot,nativeSearchWindowFacts(frozenObservationWindow(graph)),before,request.events.mark());
        }finally{if(graph!=null)graph.close();}
    }
    private void produceNativeSearchPlanning(final NativeSearchRequest request){
        NativeSearchPlanning sealed=null;NativeSearchPlanning.WindowCheck windowCheck=null;WindowOwnership profile=null;String error=null;
        try{
            requireNativeSearchRead(request);request.scope.verifyUnchanged();request.session.verifyInstalled();requireNativeSearchRead(request);
            NativeSearchSample first=null,second=null;byte[] encoded=null;String last="complete home search role not yet available";
            while(encoded==null){
                requireNativeSearchRead(request);
                if(SystemClock.elapsedRealtime()>=Math.min(request.deadline,request.started+10000))
                    throwNativeSearchSamplingExhausted(request,"sample_loop");
                try{
                    request.phase="planning_first_graph";first=readNativeSearchSample(request);
                    waitNativeSearchSample(request,first.captured+200);
                    request.phase="planning_second_graph";second=readNativeSearchSample(request);
                    request.lastCompletePair=new NativeSearchPair(first,second);
                    boolean completingInFlightPair=second.readCompleted-request.started>=10000;
                    if(completingInFlightPair&&second.readStarted-request.started>=10000)throwNativeSearchSamplingExhausted(request,"complete_pair");
                    NativeSearchPlanning.Timing timing=new NativeSearchPlanning.Timing(request.started,request.deadline,
                            first.readStarted,first.readCompleted,first.captured,second.readStarted,second.readCompleted,second.captured,SystemClock.elapsedRealtime(),completingInFlightPair);
                    NativeSearchPlanning.CaptureContext context=new NativeSearchPlanning.CaptureContext(first.windows,second.windows,
                            first.before,first.after,second.before,second.after,request.events.mark());
                    if(!completingInFlightPair)noteNativeSearchSamplingAnchor(request,first,second,timing,context);
                    try{encoded=NativeSearchPlanning.encode(request.id,first.snapshot,second.snapshot,request.session.binding(),timing,context);}
                    catch(IllegalArgumentException unavailable){
                        if(completingInFlightPair)throwNativeSearchSamplingExhausted(request,"complete_pair");
                        last=message(unavailable);request.lastSampleRejection=last;
                        request.loadingRetryClassification=null;request.loadingRetryIdentity=null;
                        if(request.retrySubmission==null&&request.samplingSubmission==null){
                            try{
                                Map<String,Object> classification=NativeSearchRole.loadingToSearch(first.snapshot,second.snapshot);
                                NativeSearchPlanning.EventMark events=request.events.mark();
                                if(events.unknown==0&&events.boundary==0&&events.events==events.content){
                                    Map<String,Object> identity=new java.util.TreeMap<String,Object>(NativeSearchRole.stableEnvelope(second.snapshot));
                                    identity.remove("origin_observation_id");request.loadingRetryIdentity=NativeAppEvidence.immutableMap(identity);
                                    request.loadingRetryClassification=classification;
                                }
                            }catch(IllegalArgumentException notLoading){/* Keep the original rejection; no recovery proof. */}
                            if(request.loadingRetryClassification!=null)throw new NativeSearchLoadingTransition();
                        }
                    }
                }catch(NoActiveWindow unavailable){
                    disqualifyNativeSearchSampling(request,"actual owned window became unavailable");
                    last=message(unavailable);request.lastSampleRejection=last;
                }catch(StaleObservation unavailable){
                    if(!unavailable.backgroundChildUnavailable)disqualifyNativeSearchSampling(request,"unclassified graph freshness rejection");
                    last=message(unavailable);request.lastSampleRejection=last;
                }
                if(encoded==null)waitNativeSearchSample(request,SystemClock.elapsedRealtime()+200);
            }
            requireNativeSearchRead(request);request.phase="planning_receipt_persist";
            if(!request.directory.isDirectory())throw new IllegalStateException("private task directory missing");
            File path=new File(request.directory,request.id+"-native-search-planning.json");
            MobiMindPrivateFiles.writeNew(path,encoded);request.path=path;requireNativeSearchRead(request);
            MobiMindPrivateFiles.Read read=MobiMindPrivateFiles.read(path,NativeSearchPlanning.MAX_BYTES,true);
            if(!java.util.Arrays.equals(encoded,read.bytes)||!sha(encoded).equals(sha(read.bytes)))
                throw new IllegalStateException("persisted planning bytes differ from this encoded request");
            read.unchangedPath();long persisted=SystemClock.elapsedRealtime();
            sealed=NativeSearchPlanning.fromSealedBytes(read.bytes,sha(encoded),request.session.binding(),persisted);requireNativeSearchRead(request);
            request.scope.verifyUnchanged();requireNativeSearchRead(request);request.phase="planning_publication_window";
            long checkStarted=SystemClock.elapsedRealtime();NativeSearchPlanning.EventMark checkBefore=request.events.mark();
            FrozenObservationWindow actual=readNativeSearchWindow(request.session,request.scope,nativeSearchReadBudget(request));
            long checkCompleted=SystemClock.elapsedRealtime();NativeSearchPlanning.EventMark checkAfter=request.events.mark();
            windowCheck=new NativeSearchPlanning.WindowCheck(nativeSearchWindowFacts(actual),checkStarted,checkCompleted,checkBefore,checkAfter);
            profile=actual.profileWindow;read.unchangedPath();requireNativeSearchRead(request);
        }catch(Exception failed){
            synchronized(request){
                if(failed instanceof NativeSearchSamplingExhausted&&((NativeSearchSamplingExhausted)failed).request==request
                        &&!request.finished&&request.failureReason==null)
                    request.samplingExhaustion=(NativeSearchSamplingExhausted)failed;
            }
            error="规划观察失败："+message(failed)+" [phase="+request.phase+"]";recordNativeSearchFailure(request,error);
        }finally{drainNativeSearchRead(request);}
        final NativeSearchPlanning value=sealed;final NativeSearchPlanning.WindowCheck check=windowCheck;
        final WindowOwnership actualProfile=profile;final String failure=error;
        boolean posted=false;
        try{posted=main.post(new Runnable(){public void run(){
            if(failure!=null){finishNativeSearchObservation(request,null,failure);return;}
            try{
                requireNativeSearchRead(request);request.session.background.requireAdmissionActive();
                if(actualProfile==null)throw new ProfileOwnershipViolation("planning publication profile proof missing");
                request.session.background.requireProfileWindow(actualProfile,actualProfile.windowId,actualProfile.taskId,SystemClock.elapsedRealtime());
                NativeSearchPlanning published=value.published(SystemClock.elapsedRealtime(),request.events.mark(),check);
                requireNativeSearchRead(request);finishNativeSearchObservation(request,published,null);
            }catch(Exception retired){finishNativeSearchObservation(request,null,"规划发布未通过："+message(retired));}
        }});}finally{
            if(!posted)finishNativeSearchObservation(request,null,"规划发布主线程未接受回执");
            if(request.finished&&!request.published&&request.path!=null)request.path.delete();
        }
    }
    /** Complete actual Graph fields only; the planning id supplies lineage, not facts. */
    private NativeActionSnapshotCheck.Snapshot nativeSearchSnapshot(Graph graph,NativeSearchSession session,String id,long earliest){
        PhoneObservation.CollectionStats stats=graph==null?null:graph.collectionStats;
        if(graph!=null&&graph.nativeSearchInvalidRawVisibility)
            throw new StaleObservation("raw_visible_nonpositive_bounds: path="+graph.nativeSearchFirstInvalidRawPath+" bounds="+graph.nativeSearchFirstInvalidRawBounds);
        if(graph!=null&&stats!=null&&graph.nativeActionNodes!=null&&(graph.nativeSearchRawVisibilityChecked!=stats.visited
                ||graph.nativeSearchRawVisibilityChecked!=graph.nativeActionNodes.size()))
            throw new StaleObservation("raw_visibility_census_coverage: checked="+graph.nativeSearchRawVisibilityChecked+" visited="+stats.visited+" nodes="+graph.nativeActionNodes.size());
        if(graph==null||!graph.nativeObservationComplete||!completeNativeObservationGraph(graph)
                ||graph.nativeActionNodes==null||graph.nativeActionWindows==null||stats==null
                ||stats.visited!=graph.nativeActionNodes.size()||graph.state.imeVisibility!=ImeVisibility.HIDDEN
                ||graph.nativeActionCapturedAt<earliest||stats.childSlotsOmitted>Integer.MAX_VALUE)
            throw new StaleObservation("native planning/effect requires a complete actual current census");
        BackgroundSession background=session.background;ProfileTarget target=background.profileTarget();
        NativeAppEvidence.requireProfileTarget(target,graph.profileWindow);
        final String actualSelectionSha;
        try{actualSelectionSha=NativeAppObservation.selectionSha(background.selection);}
        catch(Exception unavailable){throw new IllegalStateException("actual native selection evidence unavailable",unavailable);}
        if(target==null||!session.taskId.equals(graph.nativeActionTaskId)
                ||!session.authorization.authorization.sha256.equals(graph.nativeActionAuthorizationSha)
                ||!actualSelectionSha.equals(graph.nativeActionSelectionSha)||!background.ownerSha256.equals(graph.backgroundOwnerSha)
                ||!background.selection.taskTarget.targetSha256.equals(graph.nativeActionTargetSha)
                ||!background.selection.taskTarget.nativeGoal.contractSha256.equals(graph.nativeActionGoalSha)
                ||!background.generation.equals(graph.backgroundGeneration)||graph.displayId!=background.displayId()
                ||!background.selection.initialPackage.equals(graph.packageName)
                ||!background.selection.allowedPackages.equals(graph.backgroundAllowedPackages))
            throw new IllegalStateException("actual current native identity differs from this search Session");
        Map<String,Object> env=new java.util.TreeMap<String,Object>();
        env.put("task_id",graph.nativeActionTaskId);env.put("owner_sha256",graph.backgroundOwnerSha);
        env.put("target_sha256",graph.nativeActionTargetSha);env.put("authorization_sha256",graph.nativeActionAuthorizationSha);
        env.put("selection_sha256",graph.nativeActionSelectionSha);env.put("installed_set_sha256",target.apkSetSha256);
        env.put("goal_sha256",graph.nativeActionGoalSha);env.put("background_generation",graph.backgroundGeneration);
        env.put("origin_observation_id",id);env.putAll(NativeAppEvidence.profileActionIdentity(graph.profileWindow));
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
    private static Map<String,Object> nativeSearchWindowFacts(FrozenObservationWindow actual){
        if(actual==null||actual.profileWindow==null)throw new ProfileOwnershipViolation("complete actual planning window required");
        Map<String,Object> window=new LinkedHashMap<String,Object>();window.put("metadata",actual.metadata);
        window.put("package",actual.packageName);window.put("window_id",actual.windowId);window.put("display_id",actual.displayId);
        window.put("rotation",actual.rotation);window.put("left",actual.left);window.put("top",actual.top);
        window.put("right",actual.right);window.put("bottom",actual.bottom);window.put("width",actual.width);window.put("height",actual.height);
        Map<String,Object> facts=new LinkedHashMap<String,Object>();facts.put("window",window);facts.put("reported_windows",actual.windows);
        facts.put("profile_window",actual.profileWindow.evidence());facts.put("ime_visibility","hidden");
        return NativeAppEvidence.immutableMap(facts);
    }
    /** A worker window reread is recorded at its own time, never relabelled as a main-thread census. */
    private FrozenObservationWindow readNativeSearchWindow(NativeSearchSession session,QualificationScopeConfig.Bound scope,GraphBudget budget){
        checkReadBudget(budget);if(!nativeSearchSessionCurrent(session,scope))throw new ObservationAbandoned();
        requireTaskAuthorization(session.taskId,session.authorization);
        AccessibilityNodeInfo root=selectedRoot(session.background,budget);
        if(root==null)throw new NoActiveWindow();
        try{
            checkReadBudget(budget);Graph window=new Graph();window.packageName=string(root.getPackageName());
            window.windowId=root.getWindowId();window.displayId=session.background.displayId();window.bounds=new Rect();root.getBoundsInScreen(window.bounds);
            window.rotation=rotation(window.displayId);
            if(!root.isVisibleToUser()||window.bounds.isEmpty()||!session.goal.packageName.equals(window.packageName))
                throw new StaleObservation("planning/effect actual window is no longer the selected App");
            window.windowMetadata=readWindowMetadata(root,window.bounds,window.windowId,window.displayId);
            window.profileWindow=readProfileWindow(root,session.background,budget);
            NativeAppEvidence.requireProfileTarget(session.background.profileTarget(),window.profileWindow);
            DisplayManager manager=(DisplayManager)getSystemService(DISPLAY_SERVICE);Display display=manager==null?null:manager.getDisplay(window.displayId);
            if(display==null||display.getRotation()!=window.rotation)throw new StaleObservation("planning/effect actual display changed");
            android.util.DisplayMetrics metrics=new android.util.DisplayMetrics();display.getRealMetrics(metrics);
            if(metrics.widthPixels<=0||metrics.heightPixels<=0)throw new StaleObservation("actual display dimensions unavailable");
            Map<String,Object> windows=readNativeActionWindows(window,budget);checkReadBudget(budget);
            if(readImeVisibility(window.windowId,window.displayId)!=ImeVisibility.HIDDEN)throw new StaleObservation("planning/effect IME is not known hidden");
            checkReadBudget(budget);requireTaskAuthorization(session.taskId,session.authorization);
            return new FrozenObservationWindow(window.packageName,window.windowId,window.displayId,window.rotation,
                    window.bounds.left,window.bounds.top,window.bounds.right,window.bounds.bottom,metrics.widthPixels,metrics.heightPixels,
                    window.windowMetadata.bindFreshness(""),windows,window.profileWindow);
        }finally{root.recycle();}
    }

    /** Native text capture mode is bound once from the actual controller, Session,
     * immutable runtime profile and actual adapter; model output cannot select it. */
    private NativeAxMode nativeAxMode;
    private static final class NativeAxMode {
        final Object controller,nativeTask,authorization;final BackgroundSession background;final String taskId;
        NativeAxMode(Object controller,Object nativeTask,Object authorization,BackgroundSession background,String taskId){
            this.controller=controller;this.nativeTask=nativeTask;this.authorization=authorization;this.background=background;this.taskId=taskId;
        }
    }
    synchronized void bindNativeTextObservation(LocalTaskController controller,NativeAppSession nativeTask,String taskId,
            TaskAuthorization.Gate authorization,BackgroundSession background,LocalInference inference,LocalRuntimeConfig config){
        if(controller==null||nativeTask==null||authorization==null||background==null||inference==null||config==null
                ||live!=this||ownedController!=controller||!ownsAuthorization(taskId,authorization)
                ||!ownsBackground(taskId,background)||taskWeb!=null||nativeTask.authorization!=authorization
                ||!taskId.equals(nativeTask.taskId)||nativeTask.selection!=background.selection
                ||nativeTask.target!=background.selection.taskTarget||nativeTask.goal!=nativeTask.target.nativeGoal
                ||nativeTask.goal==null||nativeTask.displayId!=background.displayId()
                ||!nativeTask.generation.equals(background.generation))
            throw new IllegalArgumentException("native text observation requires the actual current controller/session/lease");
        boolean supported=NativeCtripFlightPage.supported(nativeTask.goal)
                ||(nativeTask.goal.readsXiaomiProduct()&&NativeAppGoal.XIAOMI_PACKAGE.equals(nativeTask.goal.packageName));
        boolean text=ObservationCaptureEvidence.nativeTextMode(supported,config.profile.visual(),inference.acceptsObservedImage());
        if(!text)return;
        if(nativeAxMode!=null&&nativeAxMode.authorization==authorization)
            throw new IllegalStateException("native text capture mode already bound");
        nativeAxMode=new NativeAxMode(controller,nativeTask,authorization,background,taskId);
    }
    private synchronized void bindNativeAxObservationRequest(ObservationRequest request){
        NativeAxMode mode=nativeAxMode;
        if(mode!=null&&mode.taskId.equals(request.taskId)){
            if(mode.authorization!=request.readAuthorization||mode.authorization!=taskAuthorization
                    ||mode.background!=request.background||live!=this||ownedController!=mode.controller
                    ||!ownsBackground(request.taskId,request.background))
                throw new IllegalArgumentException("bound native AX mode changed before observation admission");
            if(request.initialNativeTask!=null&&request.initialNativeTask!=mode.nativeTask)
                throw new IllegalArgumentException("native text initial Session differs");
            if(request.postEffectNativeTask!=null&&request.postEffectNativeTask!=mode.nativeTask)
                throw new IllegalArgumentException("native text post-effect Session differs");
            request.nativeAxMode=mode;
        }
    }
    private synchronized boolean nativeTextObservationAllowed(ObservationRequest request,Graph graph){
        return request.nativeAxMode!=null&&request.nativeAxMode==nativeAxMode&&live==this
                &&ownedController==nativeAxMode.controller&&nativeAxMode.taskId.equals(request.taskId)
                &&nativeAxMode.authorization==request.readAuthorization&&nativeAxMode.authorization==taskAuthorization
                &&nativeAxMode.background==request.background&&nativeObservationRecheckAllowed(request,graph);
    }
    private static final class NativeAxProduct {
        final CaptureIdentity identity;final Graph original;final String id=UUID.randomUUID().toString().replace("-","");
        final Object mode;final int publicationRecheckCount;final Map<String,Object> previousPair;
        ObservationPairSeal seal;ObservationCaptureEvidence capture;File path;
        Map<String,Object> first,second,formHistory;String firstIme,secondIme;
        ObservationEventWatermark publicationWatermark;
        ObservationEventWatermark completed;long completedAt=-1,persistedAt=-1,windowStarted=-1,windowCompleted=-1;
        boolean windowChecked,windowMatched,published;String stage="ax_seal_graph";
        final List<Map<String,Object>> rejections=new ArrayList<Map<String,Object>>();
        NativeAxProduct(CaptureIdentity identity,Graph original,Object mode){this(identity,original,mode,0,null);}
        NativeAxProduct(CaptureIdentity identity,Graph original,Object mode,int count,Map<String,Object> previous){
            this.identity=identity;this.original=original;this.mode=mode;publicationRecheckCount=count;
            previousPair=previous==null?null:ObservationCaptureEvidence.freezeMap(previous);
        }
        void reject(String at,String reason,ObservationEventWatermark watermark,long now){
            if(rejections.size()>=6)return;
            Map<String,Object> row=new java.util.LinkedHashMap<String,Object>();
            row.put("stage",at);row.put("reason",reason);row.put("checked_elapsed_ms",now);
            row.put("watermark",watermark==null?null:nativeAxWatermark(watermark));
            rejections.add(ObservationCaptureEvidence.freezeMap(row));
        }
        Map<String,Object> previousEvidence(long now,ObservationEventWatermark admission){
            Map<String,Object> e=new java.util.LinkedHashMap<String,Object>();
            e.put("captured_elapsed_ms",identity.capturedAt);
            e.put("pair_graph_started_elapsed_ms",seal.graphStartedAt);e.put("pair_graph_completed_elapsed_ms",seal.graphCompletedAt);
            e.put("complete_endpoint_elapsed_ms",completedAt);e.put("pair_sealed_elapsed_ms",seal.sealedAt);
            e.put("receipt_persisted_and_hashed_elapsed_ms",persistedAt);
            e.put("publication_check_started_elapsed_ms",windowStarted);e.put("publication_check_completed_elapsed_ms",windowCompleted);
            e.put("completed_watermark",nativeAxWatermark(completed));e.put("receipt_sha256",capture.receiptSha256);
            e.put("recheck_admitted_elapsed_ms",now);e.put("recheck_admission_watermark",nativeAxWatermark(admission));
            e.put("reason","late_typed_content");return ObservationCaptureEvidence.freezeMap(e);
        }
        Map<String,Object> rejectionFacts(ObservationEventWatermark current){
            Map<String,Object> e=new java.util.LinkedHashMap<String,Object>();List<String> reasons=new ArrayList<String>();
            for(Map<String,Object> row:rejections){String reason=(String)row.get("reason");if(!reasons.contains(reason))reasons.add(reason);}
            e.put("reason_codes",reasons);e.put("rejections",rejections);
            e.put("first_ime_visibility",firstIme);e.put("second_ime_visibility",secondIme);
            e.put("capture_watermark",nativeAxWatermark(identity.eventWatermark));
            e.put("completed_watermark",completed==null?null:nativeAxWatermark(completed));
            e.put("current_watermark",current==null?null:nativeAxWatermark(current));
            e.put("window_checked",windowChecked);e.put("window_matched",windowMatched);
            e.put("captured_elapsed_ms",identity.capturedAt);e.put("complete_endpoint_elapsed_ms",completedAt);
            e.put("sealed_elapsed_ms",seal==null?-1L:seal.sealedAt);e.put("persisted_elapsed_ms",persistedAt);
            e.put("window_started_elapsed_ms",windowStarted);e.put("window_completed_elapsed_ms",windowCompleted);
            e.put("publication_recheck_count",publicationRecheckCount);
            e.put("receipt_sha256",capture==null?null:capture.receiptSha256);e.put("previous_pair",previousPair);
            return ObservationCaptureEvidence.freezeMap(e);
        }
        Map<String,Object> evidence(long at){
            Map<String,Object> e=new java.util.LinkedHashMap<String,Object>(capture.evidence());
            e.put("schema",capture.metadataSchema());e.put("mode",capture.formHistory()?"complete_native_ax_form_history":"complete_native_ax_pair");
            e.put("capture_requested_elapsed_ms",identity.capturedAt);e.put("published_elapsed_ms",at);
            e.put("capture_age_at_publication_ms",at-identity.capturedAt);
            e.put("sample_graph_started_elapsed_ms",identity.graphStartedAt);e.put("sample_graph_completed_elapsed_ms",identity.graphCompletedAt);
            e.put("pair_graph_started_elapsed_ms",seal.graphStartedAt);e.put("pair_graph_completed_elapsed_ms",seal.graphCompletedAt);
            e.put("pair_sealed_elapsed_ms",seal.sealedAt);e.put("receipt_persisted_and_hashed_elapsed_ms",persistedAt);
            e.put("publication_check_started_elapsed_ms",windowStarted);e.put("publication_check_completed_elapsed_ms",windowCompleted);
            e.put("publication_full_graph_recheck_count",publicationRecheckCount);
            e.put("publication_full_graph_recheck_reason",publicationRecheckCount==0?null:"late_typed_content");
            e.put("publication_original_pair",previousPair);
            e.put("event_fence_complete_census_endpoint_elapsed_ms",completedAt);
            e.put("events_after_complete_census_admitted_endpoint","final_published_complete_census");
            e.put("screenshot_observed",false);e.put("screenshot_path",null);
            e.put("screenshot_is_diagnostic_only",true);e.put("events_after_complete_census_admitted",false);
            if(capture.formHistory()){
                e.put("historical_form_planning_only",true);e.put("published_pair_is_current_tree_claimed",false);
                e.put("form_history",capture.formHistoryEvidence());
                e.put("publication_event_watermark",nativeAxWatermark(publicationWatermark));
                e.put("events_after_complete_census_admitted",publicationWatermark.events!=completed.events);
                e.put("post_census_events_use","historical_form_planning_only");e.put("publication_window_matched",windowMatched);
                e.put("events_after_complete_census_admitted_endpoint","recorded_publication_watermark");
            }
            e.put("fresh_action_validation_required",true);return e;
        }
        void close(){first=null;second=null;if(path!=null&&!published){path.delete();path=null;}}
    }
    private static Map<String,Object> nativeAxWatermark(ObservationEventWatermark value){
        Map<String,Object> e=new java.util.LinkedHashMap<String,Object>();e.put("events",value.events);
        e.put("unknown",value.unknownEvents);e.put("content",value.contentEvents);e.put("boundary",value.boundaryEvents);return e;
    }
    private static boolean sameAxWatermark(ObservationEventWatermark a,ObservationEventWatermark b){
        return a!=null&&b!=null&&a.events==b.events&&a.unknownEvents==b.unknownEvents
                &&a.contentEvents==b.contentEvents&&a.boundaryEvents==b.boundaryEvents;
    }
    private static Map<String,Object> nativeAxIdentity(Graph graph){
        Map<String,Object> e=new java.util.LinkedHashMap<String,Object>();
        e.put("task_id",graph.nativeActionTaskId);e.put("owner_sha256",graph.backgroundOwnerSha);
        e.put("execution_target_sha256",graph.nativeActionTargetSha);e.put("task_authorization_sha256",graph.nativeActionAuthorizationSha);
        e.put("actual_selection_sha256",graph.nativeActionSelectionSha);e.put("native_goal_sha256",graph.nativeActionGoalSha);
        e.put("package",graph.packageName);e.put("background_generation",graph.backgroundGeneration);
        e.put("app_tree_sha256",graph.state.appTreeSha256);e.put("observation_state_sha256",graph.digest);
        e.put("display_id",graph.displayId);e.put("window_id",graph.windowId);e.put("rotation",graph.rotation);
        e.put("width",graph.nativeActionWidth);e.put("height",graph.nativeActionHeight);
        e.put("left",graph.bounds.left);e.put("top",graph.bounds.top);e.put("right",graph.bounds.right);e.put("bottom",graph.bounds.bottom);
        return e;
    }
    /** Copies every node in the original complete census, never the compact diagnostic rows. */
    private static Map<String,Object> nativeAxCensus(Graph graph){
        FrozenObservationWindow window=frozenObservationWindow(graph);
        if(window==null||!completeNativeObservationGraph(graph)||graph.collectionStats==null
                ||graph.nativeActionNodes.size()!=graph.collectionStats.visited)
            throw new IllegalArgumentException("complete native AX census missing");
        Map<String,Object> e=new java.util.LinkedHashMap<String,Object>();
        e.put("identity",nativeAxIdentity(graph));e.put("complete",true);e.put("truncated",graph.truncated);
        e.put("read_started_elapsed_ms",graph.readStartedElapsedMs);e.put("read_completed_elapsed_ms",graph.readCompletedElapsedMs);
        e.put("census_captured_elapsed_ms",graph.nativeActionCapturedAt);
        e.put("ime_visibility",graph.state.imeVisibility.name().toLowerCase(java.util.Locale.ROOT));
        e.put("visited",graph.collectionStats.visited);e.put("retained",graph.collectionStats.retained);
        e.put("pending",graph.collectionStats.pending);e.put("child_slots_omitted",graph.collectionStats.childSlotsOmitted);
        e.put("node_budget_omissions",graph.collectionStats.nodeBudgetOmissions);e.put("text_budget_omissions",graph.collectionStats.textBudgetOmissions);
        e.put("reported_windows",graph.nativeActionWindows);
        Map<String,Object> w=new java.util.LinkedHashMap<String,Object>();w.put("metadata",window.metadata);
        w.put("package",window.packageName);w.put("window_id",window.windowId);w.put("display_id",window.displayId);w.put("rotation",window.rotation);
        w.put("left",window.left);w.put("top",window.top);w.put("right",window.right);w.put("bottom",window.bottom);
        w.put("width",window.width);w.put("height",window.height);e.put("window",w);
        e.put("profile_window",graph.profileWindow==null?null:graph.profileWindow.evidence());
        e.put("profile_owner",graph.profileWindow==null?null:NativeAppEvidence.profileActionIdentity(graph.profileWindow));
        List<Map<String,Object>> nodes=new ArrayList<Map<String,Object>>();
        for(NativeActionSnapshotCheck.Node node:graph.nativeActionNodes)nodes.add(node.v);
        e.put("nodes",nodes);return ObservationCaptureEvidence.freezeMap(e);
    }
    private static boolean nativeAxEqual(Map<String,Object> before,Map<String,Object> after){
        for(String key:new String[]{"identity","nodes","reported_windows","window","profile_owner"})
            if(!java.util.Objects.equals(before.get(key),after.get(key)))return false;
        return true;
    }
    /** A complete historical form pair is a planning source only. The actual
     * bound native Session/installed profile and every full raw node remain required.
     * The pixel reader and the ordinary equal-AX factory are not widened. */
    private Map<String,Object> nativeAxFormHistory(ObservationRequest request,NativeAxProduct product,Graph after){
        if(!nativeTextObservationAllowed(request,product.original)||!nativeTextObservationAllowed(request,after)
                ||request.captured!=product.original||request.nativeAxMode!=product.mode
                ||request.background==null||product.identity.frozenWindow==null
                ||!product.identity.frozenWindow.matches(frozenObservationWindow(after)))return null;
        ProfileTarget target=request.background.profileTarget();BackgroundTaskTarget task=request.background.selection.taskTarget;
        if(target==null||task==null||!NativeCtripFlightPage.supported(task.nativeGoal)
                ||!NativeCtripFlightPage.PACKAGE.equals(target.packageName)
                ||target.versionCode!=NativeCtripFlightPage.VERSION_CODE
                ||!NativeCtripFlightPage.BASE_APK_SHA256.equals(target.apkHashes.get("base")))return null;
        requireObservationWork(request);
        try{
            Map<String,Object> binding=new java.util.LinkedHashMap<String,Object>(nativeAxIdentity(product.original));
            binding.put("observation_id",product.id);
            Map<String,Object> proof=NativeCtripFormObservation.compareAxCensuses(product.first,product.second,binding,target.apkSetSha256);
            Map<String,Object> value=new java.util.LinkedHashMap<String,Object>();
            value.put("phase",NativeCtripFlightPage.FORM);value.put("installed_set_sha256",target.apkSetSha256);
            value.put("provider_version_code",target.versionCode);value.put("provider_base_apk_sha256",target.apkHashes.get("base"));
            value.put("comparison",proof);requireObservationWork(request);
            return ObservationCaptureEvidence.freezeMap(value);
        }catch(IllegalArgumentException unclassified){return null;}
    }
    private static boolean nativeAxPublicationCovered(NativeAxProduct product,ObservationEventWatermark now){
        return product.formHistory==null?sameAxWatermark(product.completed,now):
                product.completed!=null&&now!=null&&now.onlyContentSince(product.completed)
                &&now.onlyContentSince(product.identity.eventWatermark);
    }
    private void captureNativeAxObservation(final ObservationRequest request){
        if(!observationActive(request))return;
        if(!nativeTextObservationAllowed(request,request.captured)||!request.nativeSample)
            {failObservation(request,"文本AX观察没有同次完整原生授权");return;}
        if(!observationIoBusy.compareAndSet(false,true)){failObservation(request,"先前屏幕读取尚未退出");return;}
        final CaptureIdentity identity=new CaptureIdentity(request.captured,SystemClock.elapsedRealtime(),request.eventWatermark(),true);
        final NativeAxProduct product=new NativeAxProduct(identity,request.captured,request.nativeAxMode);
        request.note(ObservationDiagnostics.Event.AX_CAPTURE_START);request.worker(true);
        submitNativeAxPair(request,product);
    }
    /** The one serial worker always reads a complete pair endpoint. A recheck
     * keeps the original A/capture clocks and never touches the settling gate. */
    private void submitNativeAxPair(final ObservationRequest request,final NativeAxProduct product){
        final CaptureIdentity identity=product.identity;
        try{observationIo.execute(new Runnable(){public void run(){
            Graph after=null;boolean retry=false;String error=null;
            try{
                requireObservationWork(request);
                product.stage=product.publicationRecheckCount==0?"ax_seal_graph":"ax_publication_graph_recheck";
                request.phase(product.stage);
                final ObservationEventWatermark start=request.eventWatermark();
                try{after=readGraph(observationBudget(request),request.background);}
                catch(NoActiveWindow busy){request.note(ObservationDiagnostics.Event.AX_GRAPH_MISSING);retry=true;
                    product.reject(product.stage,"graph_missing",request.eventWatermark(),SystemClock.elapsedRealtime());}
                catch(StaleObservation busy){request.note(ObservationDiagnostics.Event.AX_GRAPH_STALE);retry=true;
                    product.reject(product.stage,"graph_stale",request.eventWatermark(),SystemClock.elapsedRealtime());}
                // This exact endpoint is frozen before diagnostics, serialization or persistence.
                product.completed=request.eventWatermark();product.completedAt=SystemClock.elapsedRealtime();
                request.graph(product.stage,after);
                if(!retry){
                    product.first=nativeAxCensus(product.original);product.second=nativeAxCensus(after);
                    product.firstIme=product.original.state.imeVisibility.name().toLowerCase(java.util.Locale.ROOT);
                    product.secondIme=after.state.imeVisibility.name().toLowerCase(java.util.Locale.ROOT);
                    product.formHistory=nativeAxFormHistory(request,product,after);
                    boolean equal=request.captured==product.original&&identity.matches(after)&&nativeObservationRecheckAllowed(request,after)
                            &&identity.frozenWindow!=null&&identity.frozenWindow.matches(frozenObservationWindow(after))
                            &&nativeAxEqual(product.first,product.second);
                    if(!equal&&product.formHistory==null){request.note(ObservationDiagnostics.Event.AX_GRAPH_CHANGED);retry=true;
                        product.reject(product.stage,"graph_changed",request.eventWatermark(),SystemClock.elapsedRealtime());
                        recordNativeFullGraphChange(request,product.stage,product.original,after);}
                }
                boolean covered=!retry&&product.completed.onlyContentSince(start)
                        &&product.completed.onlyContentSince(identity.eventWatermark)
                        &&nativeAxPublicationCovered(product,request.eventWatermark());
                if(!covered){request.note(ObservationDiagnostics.Event.AX_PAIR_REJECTED);retry=true;
                    product.reject(product.stage,"pair_coverage",request.eventWatermark(),SystemClock.elapsedRealtime());}
                if(!retry){
                    requireObservationWork(request);
                    if(!nativeTextObservationAllowed(request,request.captured)||request.nativeAxMode!=product.mode
                            ||request.captured!=product.original)
                        throw new StaleObservation("文本AX观察的模型或任务绑定已退休");
                    final long sealed=SystemClock.elapsedRealtime();
                    product.seal=new ObservationPairSeal(identity,request.readAuthorization,after.readStartedElapsedMs,
                            after.readCompletedElapsedMs,sealed,product.completed.events,product.completed.unknownEvents);
                    Map<String,Object> binding=new java.util.LinkedHashMap<String,Object>(nativeAxIdentity(product.original));
                    binding.put("observation_id",product.id);binding.put("captured_elapsed_ms",identity.capturedAt);
                    binding.put("original_census_captured_elapsed_ms",product.original.nativeActionCapturedAt);
                    binding.put("profile_window",product.original.profileWindow==null?null:product.original.profileWindow.evidence());
                    binding.put("profile_action_identity",product.original.profileWindow==null?null:NativeAppEvidence.profileActionIdentity(product.original.profileWindow));
                    Map<String,Object> receipt=new java.util.LinkedHashMap<String,Object>();
                    receipt.put("schema",product.formHistory==null?"hepta.native-ax-capture.v1":"hepta.native-ax-form-history.v1");
                    receipt.put("kind",product.formHistory==null?ObservationCaptureEvidence.NATIVE_AX:ObservationCaptureEvidence.NATIVE_AX_FORM_HISTORY);
                    if(product.formHistory!=null){
                        receipt.put("form_history",product.formHistory);receipt.put("historical_form_planning_only",true);
                        receipt.put("published_pair_is_current_tree_claimed",false);
                    }
                    receipt.put("binding",binding);receipt.put("first",product.first);receipt.put("second",product.second);
                    receipt.put("request_started_elapsed_ms",request.started);receipt.put("request_deadline_elapsed_ms",request.deadline);
                    receipt.put("sealed_elapsed_ms",sealed);receipt.put("complete_census_endpoint_elapsed_ms",product.completedAt);
                    receipt.put("capture_watermark",nativeAxWatermark(identity.eventWatermark));receipt.put("second_start_watermark",nativeAxWatermark(start));
                    receipt.put("second_completed_watermark",nativeAxWatermark(product.completed));receipt.put("complete_census_endpoint_frozen",true);
                    receipt.put("visual_model",false);receipt.put("screenshot_present",false);receipt.put("publication_refreshes_capture_age",false);
                    receipt.put("grants_action_authority",false);receipt.put("business_completion_verified",false);
                    byte[] bytes=product.formHistory==null?ObservationCaptureEvidence.nativeAxBytes(receipt):
                            ObservationCaptureEvidence.nativeAxFormHistoryBytes(receipt);requireObservationWork(request);
                    if(!nativeAxPublicationCovered(product,request.eventWatermark())){
                        retry=true;product.reject(product.stage,"event_before_persistence",request.eventWatermark(),SystemClock.elapsedRealtime());
                    }else{
                        product.stage="ax_receipt_persist";request.phase(product.stage);
                        File path=new File(request.directory,product.id+"-native-ax.json");
                        MobiMindPrivateFiles.writeNew(path,bytes);product.path=path;
                        requireObservationWork(request);
                        MobiMindPrivateFiles.Read read=MobiMindPrivateFiles.read(path,ObservationCaptureEvidence.MAX_RECEIPT_BYTES,true);
                        product.capture=product.formHistory==null?
                                ObservationCaptureEvidence.fromSealedNativeAx(receipt,read.bytes,ObservationCaptureEvidence.hash(read.bytes)):
                                ObservationCaptureEvidence.fromSealedNativeAxFormHistory(receipt,read.bytes,ObservationCaptureEvidence.hash(read.bytes));
                        read.unchangedPath();product.persistedAt=SystemClock.elapsedRealtime();requireObservationWork(request);
                        product.stage="ax_publication_window";request.phase(product.stage);product.windowStarted=SystemClock.elapsedRealtime();
                        FrozenObservationWindow liveWindow=readFrozenObservationWindow(request,identity);
                        product.windowCompleted=SystemClock.elapsedRealtime();requireObservationWork(request);
                        product.windowChecked=true;product.windowMatched=identity.frozenWindow.matches(liveWindow);
                        if(!product.windowMatched){retry=true;
                            product.reject(product.stage,"window_mismatch",request.eventWatermark(),SystemClock.elapsedRealtime());}
                        ObservationEventWatermark checked=request.eventWatermark();
                        if(!nativeAxPublicationCovered(product,checked)){
                            retry=true;product.reject(product.stage,nativeAxLateEventReason(product,checked),checked,SystemClock.elapsedRealtime());
                        }
                    }
                }
                requireObservationWork(request);
            }catch(Exception failure){
                error="文本AX观察失败："+message(failure);
                product.reject(product.stage,"persistence_or_read_error",request.eventWatermark(),SystemClock.elapsedRealtime());
            }finally{if(after!=null)after.close();request.worker(false);observationIoBusy.set(false);}
            final boolean resample=retry;final String failure=error;boolean posted=false;
            try{posted=main.post(new Runnable(){public void run(){acceptNativeAxObservation(request,product,resample,failure);}});}
            finally{if(!posted)product.close();}
        }});}catch(RuntimeException unavailable){
            request.worker(false);observationIoBusy.set(false);
            product.reject(product.stage,"ownership_or_deadline",request.eventWatermark(),SystemClock.elapsedRealtime());
            recordNativeAxPublicationRejection(request,product,product.stage);
            if(product.publicationRecheckCount!=0)request.note(ObservationDiagnostics.Event.AX_PUBLICATION_RECHECK_REJECTED);
            product.close();failObservation(request,"文本AX观察队列不可用："+message(unavailable));
        }
    }
    private static String nativeAxLateEventReason(NativeAxProduct product,ObservationEventWatermark now){
        if(product.completed!=null&&now.onlyContentSince(product.completed)&&now.events>product.completed.events)return "late_content";
        if(product.completed==null||now.unknownEvents!=product.completed.unknownEvents
                ||now.boundaryEvents!=product.completed.boundaryEvents)return "boundary_or_unknown_event";
        return "late_untyped_event";
    }
    private static void recordNativeAxPublicationRejection(ObservationRequest request,NativeAxProduct product,String stage){
        if(request.trace==null)return;
        try{request.trace.axPublicationRejected(stage,product.first,product.second,
                product.rejectionFacts(request.eventWatermark()),SystemClock.elapsedRealtime());}
        catch(RuntimeException unavailable){/* Private diagnostics never grant publication or replace the refusal. */}
    }
    /** Only a genuinely persisted equal pair and a successful actual window check
     * can enter one complete A/C recheck for later typed-content events. */
    private boolean recheckNativeAxPublication(ObservationRequest request,NativeAxProduct product){
        if(product.formHistory!=null||request.nativeAxPublicationRecheckAttempted||product.publicationRecheckCount!=0
                ||!observationActive(request)||!request.nativeSample||request.captured!=product.original
                ||!nativeTextObservationAllowed(request,request.captured)||request.nativeAxMode!=product.mode
                ||product.seal==null||product.seal.identity!=product.identity
                ||product.seal.authorization!=taskAuthorization||product.seal.authorization!=request.readAuthorization
                ||product.capture==null||product.path==null||product.first==null||product.second==null
                ||!product.windowChecked||!product.windowMatched
                ||product.persistedAt<product.seal.sealedAt||product.windowStarted<product.persistedAt
                ||product.windowCompleted<product.windowStarted||product.completedAt<product.seal.graphCompletedAt
                ||capturePending||request.shotPending||actionWorkPending()||nativeCancellationWorkPending())return false;
        if(request.postEffectController!=null&&!postEffectObservationOwner(request))return false;
        if(request.initialController!=null&&!initialObservationOwner(request))return false;
        if(request.postEffectRetrySubmission!=null&&request.postEffectIdentityRejected
                ||request.initialRetrySubmission!=null&&request.initialIdentityRejected
                ||request.retrySubmission!=null&&request.readRecoveryRejected)return false;
        ObservationEventWatermark admission=request.eventWatermark();long now=SystemClock.elapsedRealtime();
        if(product.completed==null||admission.events<=product.completed.events
                ||!admission.onlyContentSince(product.completed)||!admission.onlyContentSince(product.identity.eventWatermark)
                ||now<product.windowCompleted||now>=request.deadline
                ||request.postEffectController!=null&&(now>=request.postEffectTaskDeadline||now>=request.postEffectTransitionDeadline)
                ||request.initialController!=null&&now>=request.initialTaskDeadline)return false;
        // No other refusal (including a window mismatch) is creditable as content.
        for(Map<String,Object> row:product.rejections)
            if(!"late_content".equals(row.get("reason")))return false;
        final NativeAxProduct replacement=new NativeAxProduct(product.identity,product.original,product.mode,1,
                product.previousEvidence(now,admission));
        if(!observationIoBusy.compareAndSet(false,true))return false;
        request.nativeAxPublicationRecheckAttempted=true;
        request.note(ObservationDiagnostics.Event.AX_PUBLICATION_RECHECK_STARTED);request.worker(true);
        product.close();submitNativeAxPair(request,replacement);return true;
    }
    private void acceptNativeAxObservation(ObservationRequest request,NativeAxProduct product,boolean retry,String error){
        try{
            if(!observationActive(request))return;
            if(error!=null){
                recordNativeAxPublicationRejection(request,product,product.stage);
                if(product.publicationRecheckCount!=0)request.note(ObservationDiagnostics.Event.AX_PUBLICATION_RECHECK_REJECTED);
                failObservation(request,error);return;
            }
            if(request.postEffectRetrySubmission!=null&&(!postEffectObservationOwner(request)||request.postEffectIdentityRejected))
                {failObservation(request,"操作后重新读取的窗口或任务身份已变化");return;}
            if(request.initialRetrySubmission!=null&&(!initialObservationOwner(request)||request.initialIdentityRejected))
                {failObservation(request,"首次页面重新读取的窗口或任务身份已变化");return;}
            if(request.retrySubmission!=null&&request.readRecoveryRejected)
                {failObservation(request,"页面已切换，本次重新观察已停止");return;}
            if(!nativeTextObservationAllowed(request,request.captured)||request.nativeAxMode!=product.mode
                    ||request.captured!=product.original)
                {failObservation(request,"封存AX观察的授权或后台租约已变化");return;}
            requireTaskAuthorization(request.taskId,taskAuthorization);
            ObservationEventWatermark accepted=request.eventWatermark();
            if(retry||!nativeAxPublicationCovered(product,accepted)){
                if(!sameAxWatermark(product.completed,accepted))
                    product.reject("ax_main_handoff",nativeAxLateEventReason(product,accepted),accepted,SystemClock.elapsedRealtime());
                recordNativeAxPublicationRejection(request,product,"ax_main_handoff");
                request.note(ObservationDiagnostics.Event.CAPTURE_EVENT_RESET);
                if(recheckNativeAxPublication(request,product))return;
                if(product.publicationRecheckCount!=0)request.note(ObservationDiagnostics.Event.AX_PUBLICATION_RECHECK_REJECTED);
                product.close();retryObservation(request,200);return;
            }
            if(product.seal==null||product.seal.identity!=product.identity
                    ||product.seal.authorization!=taskAuthorization||product.seal.authorization!=request.readAuthorization
                    ||product.capture==null||product.path==null||!product.windowChecked||!product.windowMatched
                    ||product.windowCompleted<product.windowStarted
                    ||product.windowStarted<product.persistedAt||product.persistedAt<product.seal.sealedAt)
                throw new IllegalStateException("AX完整封存或发布窗口证据缺失");
            request.phase("publish");Graph graph=request.captured;
            product.publicationWatermark=accepted;
            PhoneObservation observation=new PhoneObservation(product.id,graph.packageName,product.identity.capturedAt,
                    graph.nativeActionWidth,graph.nativeActionHeight,graph.rotation,graph.windowId,graph.bounds,null,null,graph.digest,
                    graph.state,graph.windowMetadata,graph.truncated,graph.rows,graph.backgroundGeneration,graph.backgroundBootstrapPackage,
                    graph.backgroundAllowedPackages,graph.collectionStats,new JSONObject(graph.backgroundSelectionRaw),graph.backgroundOwnerSha,
                    product.evidence(SystemClock.elapsedRealtime()),graph.profileWindow,product.capture);
            if(!observationActive(request))return;
            ObservationEventWatermark transferred=request.eventWatermark();
            // History may include typed content already recorded before DTO construction.
            // Any later event still refuses this publication rather than hiding its watermark.
            if(!sameAxWatermark(product.formHistory==null?product.completed:product.publicationWatermark,transferred)){
                product.reject("ax_before_transfer",nativeAxLateEventReason(product,transferred),transferred,SystemClock.elapsedRealtime());
                recordNativeAxPublicationRejection(request,product,"ax_before_transfer");
                request.note(ObservationDiagnostics.Event.CAPTURE_EVENT_RESET);
                if(recheckNativeAxPublication(request,product))return;
                if(product.publicationRecheckCount!=0)request.note(ObservationDiagnostics.Event.AX_PUBLICATION_RECHECK_REJECTED);
                product.close();retryObservation(request,200);return;
            }
            if(product.publicationRecheckCount!=0)request.note(ObservationDiagnostics.Event.AX_PUBLICATION_RECHECK_PASSED);
            clearSnapshot();current=observation;currentGraph=graph;currentBitmap=null;
            request.captured=null;product.published=true;
            if(request.trace!=null)request.trace.published(observation.id,SystemClock.elapsedRealtime());
            request.finished=true;request.gate.retire();activeObservation=null;request.callback.onObservation(observation);
        }catch(Exception failure){
            product.reject("ax_main_handoff","ownership_or_deadline",request.eventWatermark(),SystemClock.elapsedRealtime());
            recordNativeAxPublicationRejection(request,product,"ax_main_handoff");
            if(product.publicationRecheckCount!=0)request.note(ObservationDiagnostics.Event.AX_PUBLICATION_RECHECK_REJECTED);
            failObservation(request,"AX观察发布失败："+message(failure));
        }finally{product.close();}
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
        final boolean backgroundChildUnavailable;
        StaleObservation(String detail){this(detail,false);}
        StaleObservation(String detail,boolean backgroundChildUnavailable){super("stale:"+detail);this.backgroundChildUnavailable=backgroundChildUnavailable;}
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
    private void backgroundBeforeDispatch(String taskId,PhoneObservation expected,ActionDecision action,AccessibilityNodeInfo node,boolean nodeRequired,ActionWork work)throws Exception{
        BackgroundSession background=backgroundFor(taskId);if(background==null)return;
        requireBackgroundObservation(taskId,expected);
        if("home".equals(action.action))throw new IllegalArgumentException("后台任务不提供 HOME，也不会回退到主屏导航");
        if("click".equals(action.action)&&action.nodeId==null)throw new IllegalArgumentException("后台任务只接受已观察节点动作，不派发坐标手势");
        if(!background.allows(action.packageName))throw new IllegalArgumentException("动作应用超出本次后台范围");
        AccessibilityNodeInfo root=null;AccessibilityWindowInfo window=null;
        try{
            root=selectedRoot(background,work==null?null:work.budget());window=root==null?null:root.getWindow();
            if(root==null||window==null||background.displayId()<=Display.DEFAULT_DISPLAY||window.getDisplayId()!=background.displayId()
                    ||window.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION||root.getWindowId()<0||window.getId()!=root.getWindowId()
                    ||!expected.packageName.equals(string(root.getPackageName()))||!root.isVisibleToUser())
                throw new IllegalStateException("后台目标窗口已变化");
            background.requireActive();actionCheck(work);
            requireActualProfileTask(background,expected,window);
            if(!ownsBackground(taskId,background))throw new IllegalStateException("后台任务租约已退休");
            // A new window within the same verified owned display and package
            // invalidates this proposal; only a new observation/model run may continue.
            if(root.getWindowId()!=expected.windowId)
                throw new StaleObservation("后台同应用窗口已换代，需重新观察");
            if(nodeRequired){
                Graph selected=graphForAction(work);NodeRef ref=selected==null?null:selected.refs.get(action.nodeId);
                if(node==null||ref==null||ref.node!=node)throw new IllegalStateException("后台节点不属于本次观察");
                boolean refreshed=refreshActionNode(work,node);background.requireActive();
                if(!refreshed)throw new StaleObservation("后台节点已不可用，需重新观察");
                // Identity failures stay terminal, even when the same refresh also changes text.
                requireBackgroundNodeWindow(background,expected,node);
                if(!node.isVisibleToUser()||!node.isEnabled()
                        ||(!ref.signature.equals(nodeSignature(node,observedChildText(node,true,work==null?null:work.budget())))
                        &&!deferNativeSearchEntrySignature(taskId,expected,action,node,work)))
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
            requireActualProfileTask(background,expected,window);
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

    interface CalendarActionCallback {void onResult(CalendarActionResult result);}
    /** Produced only by this service after an actual shared-slot ActionWork.
     * The result preserves input uncertainty; it is never selected-date evidence. */
    static final class CalendarActionResult {
        private final NativeAppSession.CalendarPermit permit;
        private final CalendarInputAttempt attempt;
        private final BackgroundSession.CalendarDateInputReceipt receipt;
        final ActionOutcome outcome;
        final long confirmedElapsed,publishedElapsed;
        private final Map<String,Object> execution;
        private CalendarActionResult(NativeAppSession.CalendarPermit permit,CalendarInputAttempt attempt,
                BackgroundSession.CalendarDateInputReceipt receipt,ActionOutcome outcome,long published,Map<String,Object> execution){
            this.permit=permit;this.attempt=attempt;this.receipt=receipt;this.outcome=outcome;
            confirmedElapsed=receipt==null?-1:receipt.receivedElapsedMs;publishedElapsed=published;
            this.execution=execution==null?null:NativeAppEvidence.immutableMap(execution);
        }
        void requireSuccessfulOriginal(NativeAppSession.CalendarPermit expected,CalendarInputAttempt original){
            calendarFreshRequire(permit==expected&&attempt!=null&&attempt==original&&receipt!=null
                    &&receipt.belongsTo(permit.background(),attempt)&&outcome.accepted&&outcome.dispatched&&!outcome.stale
                    &&execution!=null&&Boolean.TRUE.equals(execution.get("effect_entered"))
                    &&Boolean.TRUE.equals(execution.get("effect_returned"))&&Boolean.TRUE.equals(execution.get("api_accepted"))
                    &&Boolean.TRUE.equals(execution.get("worker_drained"))&&Boolean.TRUE.equals(execution.get("callback_published"))
                    &&Boolean.TRUE.equals(execution.get("callback_authority_current"))&&!Boolean.TRUE.equals(execution.get("retired"))
                    &&attempt.operationId.equals(execution.get("operation_id"))
                    &&confirmedElapsed>=attempt.queuedElapsed&&publishedElapsed>=confirmedElapsed
                    &&publishedElapsed<permit.deadlineElapsed,
                    "same confirmed one-use calendar pair, actual drained worker and current callback required");
        }
        Map<String,Object> evidence()throws Exception{
            Map<String,Object> e=new java.util.LinkedHashMap<String,Object>();e.put("schema","hepta.native-calendar-action-result.v1");
            e.put("action",NativeCalendarDateIntent.ACTION);e.put("model_run_id",permit.modelRunId());
            e.put("accepted",outcome.accepted);e.put("input_may_have_been_attempted",outcome.dispatched);
            e.put("platform_pair_confirmed",receipt!=null);e.put("stale",outcome.stale);e.put("detail",outcome.detail);
            e.put("action_execution",execution);e.put("confirmed_elapsed_ms",confirmedElapsed<0?null:Long.valueOf(confirmedElapsed));
            e.put("callback_elapsed_ms",publishedElapsed);e.put("original_action_deadline_elapsed_ms",permit.deadlineElapsed);
            e.put("platform_receipt_json",receipt==null?null:receipt.evidence().toString());
            e.put("platform_request_json",receipt==null?null:receipt.requestEvidence().toString());
            e.put("automatic_replay",false);e.put("date_selection_verified",false);e.put("business_verified",false);
            return NativeAppEvidence.immutableMap(e);
        }
    }
    /** No public/package constructor exists. A closed broker probe, Map, model
     * reply or pure Consumption cannot manufacture this live action capability. */
    static final class CalendarInputAttempt {
        private final HeptaAccessibilityService issuer;
        private final LocalTaskController controller;
        private final NativeAppSession.CalendarPermit permit;
        private final Cancellation cancel;
        private ActionWork liveWork;
        private Map<String,Object> values;
        private boolean brokerCallConsumed,sendConsumed,workerRetired;
        final String operationId;final long queuedElapsed;
        private CalendarInputAttempt(HeptaAccessibilityService issuer,LocalTaskController controller,
                NativeAppSession.CalendarPermit permit,ActionWork work){
            this.issuer=issuer;this.controller=controller;this.permit=permit;liveWork=work;cancel=work.cancel;
            operationId=work.state.operationId;queuedElapsed=work.state.queuedElapsed;
        }
        void requirePermitProducer(NativeAppSession.CalendarPermit actual,boolean entered){
            ActionWork work;
            synchronized(this){calendarFreshRequire(!workerRetired&&liveWork!=null&&permit==actual,
                    "same live private calendar input producer required");work=liveWork;}
            work.check();controller.requireNativeCalendarActionOwner(permit);
            calendarFreshRequire(issuer.activeAction==work&&issuer.lastActionExecution==work.state&&actionSlot.pending()
                    &&work.cancel==cancel&&work.background==permit.background()&&work.authorization==permit.session().authorization
                    &&work.expected==permit.observationForAction(issuer,controller)&&work.state.deadlineElapsed==permit.deadlineElapsed
                    &&work.state.effectEntered()==entered,"calendar input does not own the original shared action slot");
            permit.requireActionCurrent(issuer,controller);
        }
        Map<String,Object> executionBeforeInput(){requirePermitProducer(permit,false);return liveWork.state.evidence();}
        private void prepare()throws Exception{
            requirePermitProducer(permit,false);liveWork.phase("attempt_journal");values=permit.consumeInput(this);
            permit.requireInputOriginal(this);requirePermitProducer(permit,false);
        }
        /** Consumed before any socket attempt. The returned values have no input
         * authority without this same private object at the final send fence. */
        Map<String,Object> beginBrokerCall(BackgroundSession actual,Cancellation original)throws Exception{
            synchronized(this){
                if(brokerCallConsumed){if(liveWork!=null)liveWork.state.retire("controller_abandoned");
                    throw new IllegalStateException("calendar broker call already consumed");}
                brokerCallConsumed=true;
                calendarFreshRequire(actual==permit.background()&&original==cancel&&values!=null,
                        "calendar broker must use the same background and cancellation");
            }
            requirePermitProducer(permit,true);
            permit.requireInputPure(issuer,this,SystemClock.elapsedRealtime());return values;
        }
        /** Pure final fence only: BG has connected its sole socket already.
         * Never recursively issue profile/policy RPC or read a new graph here. */
        void requireBeforeSend(BackgroundSession actual,Cancellation original){
            synchronized(this){
                calendarFreshRequire(!sendConsumed&&brokerCallConsumed&&actual==permit.background()&&original==cancel,
                        "same unspent original calendar socket send required");sendConsumed=true;
            }
            requirePermitProducer(permit,true);permit.requireInputPure(issuer,this,SystemClock.elapsedRealtime());
        }
        private synchronized void workerDrained(){
            workerRetired=true;liveWork=null; // A receipt cannot retain closed Graph/Node references.
        }
    }
    void performNativeCalendarDate(final LocalTaskController controller,final NativeAppSession.CalendarPermit permit,
            final Cancellation originalCancel,final CalendarActionCallback callback){
        final long queued=SystemClock.elapsedRealtime();
        if(permit==null||controller==null||originalCancel==null||callback==null)
            throw new IllegalArgumentException("actual calendar permit/controller/cancellation/callback required");
        permit.claimActionProducer(this,controller);
        final Cancellation ownedCancel=new Cancellation(){public boolean isCancelled(){return originalCancel.isCancelled()||permit.actionRetired();}};
        final QualificationScopeConfig.Bound scope=scopeFor(permit.session().taskId);
        final TaskAuthorization.Gate auth=permit.session().authorization;final BackgroundSession background=permit.background();
        final String task=permit.session().taskId;
        final CalendarActionCallback failureCallback=new CalendarActionCallback(){public void onResult(CalendarActionResult result){callback.onResult(result);}};
        boolean posted=main.post(new Runnable(){public void run(){
            Graph snapshot=null;
            try{
                controller.requireNativeCalendarActionOwner(permit);
                calendarFreshRequire(nativeSearchAllowsLegacyObservation(task)&&ownsScope(task,scope)&&!scope.restricted()
                        &&ownsAuthorization(task,auth)&&ownsBackground(task,background)&&taskWeb==null
                        &&!ownedCancel.isCancelled()&&SystemClock.elapsedRealtime()<permit.deadlineElapsed
                        &&!actionWorkPending()&&!nativeCancellationWorkPending()&&activeObservation==null
                        &&activeNativeSearchObservation==null&&!observationReadWorkPending()&&!capturePending,
                        "calendar action requires the same idle owned action lane");
                PhoneObservation expected=permit.observationForAction(HeptaAccessibilityService.this,controller);
                permit.requireActionCurrent(HeptaAccessibilityService.this,controller);
                calendarFreshRequire(expected==current&&currentGraph!=null&&expected.capture==null
                        &&ObservationCaptureEvidence.PIXELS.equals(expected.captureKind),"actual fresh calendar pixels are not current");
                snapshot=currentGraph.copyForAction(null,null);
                final ActionWork work=new ActionWork(task,expected,permit.modelRunId(),scope,auth,background,ownedCancel,
                        snapshot,null,queued,permit.deadlineElapsed,null);
                if(!actionSlot.acquire(work.state))throw new IllegalStateException("calendar action slot is occupied");
                activeAction=work;lastActionExecution=work.state;snapshot=null;
                final CalendarInputAttempt input=new CalendarInputAttempt(HeptaAccessibilityService.this,controller,permit,work);
                try{actionIo.execute(new Runnable(){public void run(){runNativeCalendarDate(controller,permit,input,work,callback);}});}
                catch(java.util.concurrent.RejectedExecutionException refused){
                    work.state.retire("queue_rejected");work.graph.close();work.state.drained();
                    if(activeAction==work)activeAction=null;actionSlot.release(work.state);input.workerDrained();
                    work.state.publish(ownedCancel.isCancelled(),work.currentLease()&&lastActionExecution==work.state);
                    permit.retireInputTracking();
                    callback.onResult(new CalendarActionResult(permit,input,null,new ActionOutcome(false,false,false,
                            "日期动作队列没有接受请求；一次名额不恢复").withActionExecution(actionDiagnosticEvidence(work)),
                            SystemClock.elapsedRealtime(),work.state.evidence()));
                }catch(RuntimeException uncertainSubmission){
                    // Same original queue rule: unknown submission is not physical drain.
                    work.state.retire("controller_abandoned");
                }
            }catch(Exception refused){
                if(snapshot!=null)snapshot.close();permit.close();
                failureCallback.onResult(new CalendarActionResult(permit,null,null,new ActionOutcome(false,false,
                        refused instanceof StaleObservation,message(refused)),SystemClock.elapsedRealtime(),null));
            }
        }});
        if(!posted){permit.close();callback.onResult(new CalendarActionResult(permit,null,null,
                new ActionOutcome(false,false,false,"日期动作主线程未接受请求"),SystemClock.elapsedRealtime(),null));}
    }
    private void requireCalendarInputGraph(ActionWork work,NativeAppSession.CalendarPermit permit)throws Exception{
        work.phase("graph_read");permit.requireForAction(permit.session(),work.background);
        Graph actual=readGraph(work.budget(),work.background);
        try{
            work.check();calendarFreshRequire(actual!=null&&!actual.truncated&&!work.graph.truncated
                    &&work.graph.sameWindowAndTree(actual)&&frameKey(work.graph).equals(frameKey(actual))
                    &&actual.windowId==work.expected.windowId&&actual.displayId==permit.session().displayId
                    &&actual.rotation==work.expected.rotation,
                    "calendar complete graph/window changed before its one input");
            requireSameProfileOwner(work.expected.profileWindow,actual.profileWindow);
            requireScopeObservation(work.state.taskId,work.expected);
            requireAuthorizationObservation(work.state.taskId,work.authorization,work.expected);
            requireBackgroundObservation(work.state.taskId,work.expected);
            permit.requireActionCurrent(this,ownedController);
        }finally{if(actual!=null)actual.close();}
        work.check();
    }
    private void runNativeCalendarDate(final LocalTaskController controller,final NativeAppSession.CalendarPermit permit,
            final CalendarInputAttempt input,final ActionWork work,final CalendarActionCallback callback){
        ActionOutcome result;BackgroundSession.CalendarDateInputReceipt receipt=null;
        try{
            work.phase("worker_started");work.check();input.prepare();
            requireCalendarInputGraph(work,permit);permit.requireInputOriginal(input);
            // This original fence performs the actual live-profile and policy checks before effect entry.
            enterActionEffect(work);input.requirePermitProducer(permit,true);
            receipt=work.background.performCalendarDate(input,work.cancel);
            calendarFreshRequire(receipt!=null&&receipt.belongsTo(work.background,input),"actual same-attempt platform receipt missing");
            actionEffectReturned(work,Boolean.TRUE);work.check();
            result=new ActionOutcome(true,true,false,"日期选择输入已由平台确认；必须重新观察表单，尚未证明目标日期");
        }catch(Exception refused){
            result=new ActionOutcome(false,work.state.effectEntered(),refused instanceof StaleObservation,
                    "日期选择未完整确认；不重放："+message(refused));
            if(work.state.effectEntered())try{actionEffectReturned(work,null);}catch(IllegalStateException alreadyReturned){}
        }finally{
            work.graph.close();work.logMarker(work.state.drained());
            if(activeAction==work)activeAction=null;actionSlot.release(work.state);input.workerDrained();
            permit.retireInputTracking();
        }
        final ActionOutcome computed=result;final BackgroundSession.CalendarDateInputReceipt actualReceipt=receipt;
        main.post(new Runnable(){public void run(){
            boolean currentLease=work.currentLease()&&lastActionExecution==work.state,stopped=work.cancel.isCancelled();
            boolean allowed=work.state.publish(stopped,currentLease);
            ActionOutcome delivered=allowed?computed:new ActionOutcome(false,computed.dispatched,false,
                    "日期输入回执到达时任务已退休；保留真实输入事实，不重放");
            delivered=delivered.withScope(callbackScopeEvidence(work.state.taskId,work.scope,currentLease,stopped))
                    .withAuthorization(callbackAuthorizationEvidence(work.authorization,currentLease,stopped))
                    .withBackground(work.background.evidence()).withActionExecution(actionDiagnosticEvidence(work));
            callback.onResult(new CalendarActionResult(permit,input,actualReceipt,delivered,SystemClock.elapsedRealtime(),work.state.evidence()));
        }});
    }
    /** Actual current post-effect Phone plus private persisted source record. */
    static final class CalendarSelectionObservation {
        private final HeptaAccessibilityService issuer;private final LocalTaskController controller;
        private final NativeAppSession.CalendarPermit permit;private final PhoneObservation observed;
        final CalendarActionResult result;final NativeAppEvidence.Frame frame;
        private final File record;private final String recordSha;
        private CalendarSelectionObservation(HeptaAccessibilityService issuer,LocalTaskController controller,
                NativeAppSession.CalendarPermit permit,CalendarActionResult result,PhoneObservation observed,
                NativeAppEvidence.Frame frame,File record,String sha){
            this.issuer=issuer;this.controller=controller;this.permit=permit;this.result=result;this.observed=observed;
            this.frame=frame;this.record=record;recordSha=sha;
        }
        void requireBound(NativeAppSession.CalendarPermit actual)throws Exception{
            calendarFreshRequire(actual==permit,"same original calendar permit required");
            issuer.requireCalendarSelectionCurrent(controller,permit,result,observed);
            MobiMindPrivateFiles.Read read=MobiMindPrivateFiles.read(record,2*1024*1024,true);
            calendarFreshRequire(recordSha.equals(MobiMindContract.sha(read.bytes)),"calendar FORM record changed");
            read.unchangedPath();issuer.requireCalendarSelectionCurrent(controller,permit,result,observed);
        }
        Map<String,Object> evidence(){
            Map<String,Object> e=new java.util.LinkedHashMap<String,Object>();e.put("schema","hepta.native-calendar-form-publication.v1");
            e.put("frame",frame.evidence());e.put("source_record_sha256",recordSha);e.put("record",record.getName());
            e.put("private_actual_service_producer",true);e.put("date_selection_verified",false);
            return NativeAppEvidence.immutableMap(e);
        }
    }
    private void requireCalendarSelectionCurrent(LocalTaskController controller,NativeAppSession.CalendarPermit permit,
            CalendarActionResult result,PhoneObservation observed){
        controller.requireNativeCalendarActionOwner(permit);
        permit.requireSelectionPublication(result,SystemClock.elapsedRealtime());
        synchronized(this){
            calendarFreshRequire(live==this&&ownedController==controller&&ownsAuthorization(permit.session().taskId,permit.session().authorization)
                    &&ownsBackground(permit.session().taskId,permit.background())&&taskWeb==null&&current==observed
                    &&observed!=null&&currentGraph!=null&&currentBitmap!=null&&!currentBitmap.isRecycled()
                    &&!actionWorkPending()&&!nativeCancellationWorkPending()&&activeObservation==null
                    &&activeNativeSearchObservation==null&&!observationReadWorkPending()&&!capturePending,
                    "actual complete post-effect FORM is not current or an owned lane is pending");
        }
        long now=SystemClock.elapsedRealtime();
        calendarFreshRequire(observed.capture==null&&ObservationCaptureEvidence.PIXELS.equals(observed.captureKind)
                &&observed.capturedElapsedMillis>result.confirmedElapsed
                &&now>=observed.capturedElapsedMillis&&now-observed.capturedElapsedMillis<=NativeCalendarDateEnvelope.FRESH_CAPTURE_MS,
                "post-effect FORM must be a new fresh pixel observation");
        requireTaskAuthorization(permit.session().taskId,permit.session().authorization);
        requireScopeObservation(permit.session().taskId,observed);
        requireAuthorizationObservation(permit.session().taskId,permit.session().authorization,observed);
        requireBackgroundObservation(permit.session().taskId,observed);
        permit.requireSelectionPublication(result,SystemClock.elapsedRealtime());
    }
    CalendarSelectionObservation calendarSelectionObservation(LocalTaskController controller,NativeAppSession.CalendarPermit permit,
            CalendarActionResult result,PhoneObservation observed,File directory)throws Exception{
        permit.requireSelectionOriginal(result);requireCalendarSelectionCurrent(controller,permit,result,observed);
        File expected=new File(new File(getFilesDir(),"control-tasks"),permit.session().taskId).getCanonicalFile();
        calendarFreshRequire(expected.equals(directory.getCanonicalFile())&&directory.isDirectory(),"same private calendar task directory required");
        File record=new File(directory,"native-calendar-selection-frame.json");
        byte[] bytes=observed.toEvidenceJson().toString(2).getBytes(StandardCharsets.UTF_8);
        calendarFreshRequire(bytes.length<=2*1024*1024&&record.createNewFile(),"new bounded private calendar FORM record required");
        if(!record.setReadable(false,false)||!record.setWritable(false,false)||!record.setReadable(true,true)||!record.setWritable(true,true))
            throw new IllegalStateException("calendar FORM record could not be private");
        try(FileOutputStream out=new FileOutputStream(record)){out.write(bytes);out.getFD().sync();}
        MobiMindPrivateFiles.Read actual=MobiMindPrivateFiles.read(record,2*1024*1024,true);
        calendarFreshRequire(java.util.Arrays.equals(bytes,actual.bytes),"calendar FORM source readback differs");actual.unchangedPath();
        String sha=MobiMindContract.sha(actual.bytes);
        NotesCompletionEvidence.Frame completion=controller.calendarSelectionCompletionFrame(permit,result,observed);
        NativeAppEvidence.Frame frame=NativeAppObservation.copy(permit.session().taskId,permit.session().authorization,
                permit.background(),observed,completion,sha);
        permit.requireSelectionOriginal(result);requireCalendarSelectionCurrent(controller,permit,result,observed);
        CalendarSelectionObservation proof=new CalendarSelectionObservation(this,controller,permit,result,observed,frame,record,sha);
        proof.requireBound(permit);return proof;
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
            if(!nativeSearchAllowsLegacyObservation(taskId)||!ownsScope(taskId,captured)||!ownsAuthorization(taskId,capturedAuthorization)||capturedAuthorization!=expectedAuthorization
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
                        boolean currentLease=work.currentLease()&&lastActionExecution==work.state,stopped=cancel.isCancelled();
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
    boolean actionWorkPending(){return actionSlot.pending()||ProfilePermissionUiSession.workPending();}
    void retireActionWork(String taskId,String reason){
        retireNativeSearch(taskId,reason);
        profilePermissionUi.retire(taskId,reason);
        ActionWork work=activeAction;if(work!=null&&work.state.taskId.equals(taskId))work.state.retire(reason);
    }
    JSONObject actionExecutionEvidence(String taskId){
        ActionExecutionState value=lastActionExecution;
        return value==null||!value.taskId.equals(taskId)?null:new JSONObject(value.evidence());
    }
    private volatile SearchActionWork activeSearchAction;
    private static final int NATIVE_SEARCH_CURRENT_C_READ_LIMIT=8;
    /** A memory-only capability from the last unclaimed census fence. It
     * never creates another model intent, Attempt, action slot or deadline. */
    static final class NativeSearchFinalCensusResampleProof {
        private final HeptaAccessibilityService issuer;private final SearchActionWork work;
        private final NativeSearchRole role;private final Graph oldC,oldD;
        private final NativeActionSnapshotCheck.Snapshot current,latest;
        private final NativeSearchPlanning.EventMark rejected;private final long issuedElapsed;
        private final java.util.concurrent.atomic.AtomicBoolean consumed=new java.util.concurrent.atomic.AtomicBoolean();
        private NativeSearchFinalCensusResampleProof(HeptaAccessibilityService issuer,SearchActionWork work,
                NativeSearchRole role,Graph latestGraph,NativeSearchPlanning.EventMark rejected,long now){
            this.issuer=issuer;this.work=work;this.role=role;oldC=work.currentGraph;oldD=latestGraph;
            current=work.currentSnapshot;latest=work.latestSnapshot;this.rejected=rejected;issuedElapsed=now;
        }
        void consume(NativeSearchSession.Attempt actual,NativeSearchRole actualRole,long now){
            if(actual!=work.attempt||actualRole!=role||now<issuedElapsed||now>=actual.deadlineElapsed)
                throw new IllegalStateException("same original unclaimed census proof required");
            work.check();actual.requireUnclaimedRevalidated(now);
            synchronized(issuer.nativeSearchEventLock){
                long observedNow=SystemClock.elapsedRealtime();
                if(work.pendingFinalCensusResample!=this||work.finalCensusResamples!=0
                        ||issuer.activeSearchAction!=work||issuer.nativeSearchTrackedAction!=work||issuer.lastActionExecution!=work.state
                        ||work.currentGraph!=null||oldC==null||oldD==null||!oldC.refs.isEmpty()||!oldD.refs.isEmpty()
                        ||work.currentSnapshot!=current||work.latestSnapshot!=latest
                        ||work.finalPreclaimRejectedWatermark!=rejected||!work.typedFinalPreclaimContentRejected
                        ||work.firstPostDEventRejected||work.typedAfterTargetRefreshPostDEventRejected
                        ||!work.currentNodeIdentityChecked||!work.ancestorChainChecked||!work.windowsChecked||work.profileBeforeEffect==null
                        ||work.platformCallInvoked||work.state.effectEntered()||work.state.retired()||work.state.isDrained()
                        ||work.cancel.isCancelled()||observedNow<issuedElapsed||observedNow>=work.state.deadlineElapsed
                        ||observedNow>=work.session.chainDeadlineElapsed)
                    throw new IllegalStateException("closed old graphs and live exact census boundary required");
                NativeSearchPlanning.EventMark observed=work.events.mark();
                requireNativeSearchPairEvents(work.pairStart,observed);
                if(!observed.monotonicSince(rejected)||!consumed.compareAndSet(false,true))
                    throw new IllegalStateException("one unchanged-identity census resample capability required");
            }
        }
    }
    /** Local control flow only: every other stale/error path remains terminal. */
    private static final class NativeSearchFinalCensusChanged extends IllegalStateException {
        private static final long serialVersionUID=1L;
        final NativeSearchFinalCensusResampleProof proof;
        private NativeSearchFinalCensusChanged(NativeSearchFinalCensusResampleProof proof){
            super("new search final unclaimed census was invalidated by an actual content event");this.proof=proof;
        }
    }
    /** A new typed intent owns its own current C NodeRef; no PhoneObservation is manufactured. */
    private final class SearchActionWork {
        final NativeSearchSession.Attempt attempt;final NativeSearchSession session;final QualificationScopeConfig.Bound scope;
        final Cancellation cancel;final ActionExecutionState state;final SearchEvents events;
        Graph currentGraph;boolean platformCallInvoked;JSONObject sealedDiagnostic;String sealedDiagnosticSha;
        final File planningDirectory;final int planningReadOrdinal;
        final java.util.concurrent.atomic.AtomicBoolean callbackQueued=new java.util.concurrent.atomic.AtomicBoolean();
        volatile boolean replanDrainUncertain,replanDrainMarkerCompleted;
        volatile long replanDrainMarkerElapsed=-1;
        NativeSearchRole.RejectedBannerMotion bannerRefusal;
        NativeSearchPlanning.EventMark bannerRefusalWatermark;
        boolean firstPostDEventRejected;NativeSearchPlanning.EventMark firstRejectedWatermark;
        // Only the exact root/ancestor refresh fence may offer the second preclaim cause.
        boolean typedAfterTargetRefreshPostDEventRejected;
        NativeSearchPlanning.EventMark afterTargetRefreshRejectedWatermark;
        long afterTargetRefreshEventsElapsed=-1;
        long finalPreclaimEventsElapsed=-1;NativeSearchPlanning.EventMark finalPreclaimRejectedWatermark;
        boolean typedFinalPreclaimContentRejected;int finalCensusResamples;
        NativeSearchFinalCensusResampleProof pendingFinalCensusResample;
        final List<Map<String,Object>> discardedFinalCensuses=new ArrayList<Map<String,Object>>();
        long latestReadReturnedElapsed=-1,latestSnapshotCompletedElapsed=-1,roleComparedElapsed=-1,firstFinalEventsElapsed=-1;
        // Complete immutable values are retained immediately; diagnostic copies are made before drain.
        NativeActionSnapshotCheck.Snapshot currentSnapshot,latestSnapshot;
        Map<String,Object> roleProof;
        final List<Map<String,Object>> currentReadAttempts=new ArrayList<Map<String,Object>>();
        NativeSearchPlanning.EventMark pairStart,pairCompleted,effectWatermark;
        WindowOwnership profileBeforeEffect;boolean currentNodeIdentityChecked,ancestorChainChecked,windowsChecked;
        SearchActionWork(NativeSearchSession.Attempt attempt,QualificationScopeConfig.Bound scope,Cancellation cancel){
            this.attempt=attempt;session=attempt.session;this.scope=scope;this.cancel=cancel;
            planningDirectory=nativeSearchPlanningDirectory;planningReadOrdinal=taskObservationAdmissions;
            int window=((Number)attempt.offer.planning.second.env.get("window_id")).intValue();
            state=new ActionExecutionState(UUID.randomUUID().toString().replace("-",""),session.taskId,attempt.modelRunId,
                    attempt.offer.planning.id,session.authorization.authorization.sha256,window,session.background.displayId(),
                    session.background.generation,attempt.startedElapsed,attempt.deadlineElapsed,
                    new ActionExecutionState.Clock(){public long elapsedRealtime(){return SystemClock.elapsedRealtime();}});
            events=new SearchEvents(session.background.displayId(),session.goal.packageName);events.window=window;
        }
        boolean currentLease(){
            if(!nativeSearchSessionCurrent(session,scope)||state.displayId!=session.background.displayId()
                    ||!state.backgroundGeneration.equals(session.background.generation))return false;
            try{attempt.requireLive(SystemClock.elapsedRealtime());return true;}catch(RuntimeException retired){return false;}
        }
        void check(){state.check(cancel.isCancelled(),currentLease());}
        GraphBudget budget(){return new GraphBudget(){public void check(){SearchActionWork.this.check();}
            public Cancellation cancellation(){return cancel;}public long deadline(){return state.deadlineElapsed;}};}
        Cancellation boundedCancellation(){return new Cancellation(){public boolean isCancelled(){
            try{check();return false;}catch(RuntimeException retired){return true;}
        }};}
        void phase(String phase){check();marker(state.phase(phase));}
        void marker(Map<String,Object> value){try{android.util.Log.i("HeptaAction",new JSONObject(value).toString());}catch(RuntimeException ignored){}}
        void requireFirstFinalEvents(){
            check();
            synchronized(nativeSearchEventLock){
                firstFinalEventsElapsed=SystemClock.elapsedRealtime();
                NativeSearchPlanning.EventMark observed=events.mark();
                if(!sameSearchEvents(pairCompleted,observed)){
                    firstPostDEventRejected=true;firstRejectedWatermark=observed;
                    throw new StaleObservation("new search intent received an event after its complete current D census");
                }
            }
        }
        /** Called only after C's full actual target/ancestor chain and root metadata
         * match D, before this helper returns and before any attempt/effect claim. */
        void requireAfterTargetRefreshEvents(){
            check();
            // Session locking remains outside the event-routing lock.
            attempt.requireUnclaimedRevalidated(SystemClock.elapsedRealtime());
            synchronized(nativeSearchEventLock){
                afterTargetRefreshEventsElapsed=SystemClock.elapsedRealtime();
                NativeSearchPlanning.EventMark observed=events.mark();
                if(!sameSearchEvents(pairCompleted,observed)){
                    afterTargetRefreshRejectedWatermark=observed;
                    if(firstPostDEventRejected||firstFinalEventsElapsed<0
                            ||afterTargetRefreshEventsElapsed<firstFinalEventsElapsed
                            ||afterTargetRefreshEventsElapsed>=state.deadlineElapsed
                            ||afterTargetRefreshEventsElapsed>=session.chainDeadlineElapsed
                            ||cancel.isCancelled()||currentGraph==null||currentSnapshot==null||latestSnapshot==null||roleProof==null
                            ||!currentNodeIdentityChecked||ancestorChainChecked||windowsChecked
                            ||platformCallInvoked||state.effectEntered()||state.retired()||state.isDrained()
                            ||activeSearchAction!=this||nativeSearchTrackedAction!=this)
                        throw new StaleObservation("new search root-refresh event is outside the live unclaimed pre-effect boundary");
                    // Unknown, window/boundary and untyped events never set this typed cause.
                    requireNativeSearchPairEvents(pairCompleted,observed);
                    typedAfterTargetRefreshPostDEventRejected=true;
                    throw new StaleObservation("new search intent received an event after its complete current D census");
                }
            }
        }
        boolean hasNoEffectReplanFence(){
            if(bannerRefusal!=null)return !firstPostDEventRejected&&!typedAfterTargetRefreshPostDEventRejected;
            return firstPostDEventRejected!=typedAfterTargetRefreshPostDEventRejected;
        }
        NativeSearchPlanning.EventMark noEffectRejectionWatermark(){
            if(!hasNoEffectReplanFence())throw new IllegalStateException("exactly one actual preclaim event fence required");
            if(bannerRefusal!=null)return bannerRefusalWatermark;
            return firstPostDEventRejected?firstRejectedWatermark:afterTargetRefreshRejectedWatermark;
        }
        String noEffectRejectionReason(){
            if(!hasNoEffectReplanFence())throw new IllegalStateException("exactly one actual preclaim event fence required");
            if(bannerRefusal!=null)return "overlapping_blank_home_banner_before_claim";
            return firstPostDEventRejected?"post_D_event_before_target_refresh":"post_D_event_after_target_refresh_before_claim";
        }
        /** The only recovery boundary is after the complete window/profile/policy
         * checks and before attempt_journal/claim. Later fences cannot issue it. */
        void requireFinalPreclaimEvents(NativeSearchRole role,Graph latestGraph){
            check();attempt.requireUnclaimedRevalidated(SystemClock.elapsedRealtime());requireFinalProfileClock();
            synchronized(nativeSearchEventLock){
                finalPreclaimEventsElapsed=SystemClock.elapsedRealtime();
                NativeSearchPlanning.EventMark observed=events.mark();
                if(sameSearchEvents(pairCompleted,observed))return;
                // Always preserve the actual rejection, including ineligible event kinds.
                finalPreclaimRejectedWatermark=observed;
                if(firstPostDEventRejected||typedAfterTargetRefreshPostDEventRejected||firstFinalEventsElapsed<0
                        ||afterTargetRefreshEventsElapsed<firstFinalEventsElapsed
                        ||finalPreclaimEventsElapsed<afterTargetRefreshEventsElapsed
                        ||finalPreclaimEventsElapsed>=state.deadlineElapsed||finalPreclaimEventsElapsed>=session.chainDeadlineElapsed
                        ||cancel.isCancelled()||currentGraph==null||latestGraph==null||currentSnapshot==null||latestSnapshot==null||role==null||roleProof==null
                        ||!currentNodeIdentityChecked||!ancestorChainChecked||!windowsChecked||profileBeforeEffect==null
                        ||finalPreclaimEventsElapsed>=profileBeforeEffect.expiresElapsedMs
                        ||platformCallInvoked||state.effectEntered()||state.retired()||state.isDrained()
                        ||activeSearchAction!=this||nativeSearchTrackedAction!=this||lastActionExecution!=state)
                    throw new StaleObservation("new search final census event is outside the live unclaimed boundary");
                requireNativeSearchPairEvents(pairStart,observed);
                requireNativeSearchPairEvents(pairCompleted,observed);
                typedFinalPreclaimContentRejected=true;
                if(finalCensusResamples!=0||pendingFinalCensusResample!=null||currentReadAttempts.size()>=NATIVE_SEARCH_CURRENT_C_READ_LIMIT)
                    throw new StaleObservation("new search final census cannot replace its spent resample/read budget");
                pendingFinalCensusResample=new NativeSearchFinalCensusResampleProof(HeptaAccessibilityService.this,this,role,latestGraph,observed,finalPreclaimEventsElapsed);
                throw new NativeSearchFinalCensusChanged(pendingFinalCensusResample);
            }
        }
        void discardFinalCensusForResample(NativeSearchFinalCensusResampleProof proof){
            check();
            if(proof==null||proof!=pendingFinalCensusResample)
                throw new IllegalStateException("actual final-census failure capability required");
            Map<String,Object> old=new LinkedHashMap<String,Object>();
            old.put("ordinal",finalCensusResamples+1);old.put("reason","content_event_at_last_preclaim_fence");
            old.put("current_C",NativeSearchPlanning.snapshot(currentSnapshot));old.put("latest_D",NativeSearchPlanning.snapshot(latestSnapshot));
            old.put("role_comparison",roleProof);old.put("pair_start_watermark",pairStart.evidence());
            old.put("D_completed_watermark",pairCompleted.evidence());old.put("rejection_watermark",finalPreclaimRejectedWatermark.evidence());
            old.put("checked_elapsed_ms",finalPreclaimEventsElapsed);old.put("original_attempt_deadline_elapsed_ms",attempt.deadlineElapsed);
            old.put("same_attempt",true);old.put("model_reissued",false);old.put("effect_entered",state.effectEntered());old.put("platform_call_invoked",platformCallInvoked);
            // D and all temporary nodes have already closed in the round's finally.
            Graph previous=currentGraph;currentGraph=null;if(previous!=null)previous.close();
            old.put("old_C_graph_closed",previous!=null&&previous.refs.isEmpty());
            old.put("old_D_graph_closed",proof.oldD!=null&&proof.oldD.refs.isEmpty());
            discardedFinalCensuses.add(old);
            attempt.discardRevalidationForFinalCensus(proof,SystemClock.elapsedRealtime());
            finalCensusResamples++;old.put("old_revalidation_discarded",true);pendingFinalCensusResample=null;
            // First/second rejection latches were false; never clear a rejected cause.
            currentSnapshot=null;latestSnapshot=null;roleProof=null;pairCompleted=null;effectWatermark=null;
            profileBeforeEffect=null;currentNodeIdentityChecked=false;ancestorChainChecked=false;windowsChecked=false;
            latestReadReturnedElapsed=-1;latestSnapshotCompletedElapsed=-1;roleComparedElapsed=-1;firstFinalEventsElapsed=-1;
            afterTargetRefreshEventsElapsed=-1;finalPreclaimEventsElapsed=-1;finalPreclaimRejectedWatermark=null;typedFinalPreclaimContentRejected=false;
            // pairStart and the same live SearchEvents tracker deliberately survive.
            check();
        }
        void requireFinalEvents(){
            check();if(!sameSearchEvents(pairCompleted,events.mark()))
                throw new StaleObservation("new search intent received an event after its complete current D census");
        }
        void requireFinalProfile(){
            check();WindowOwnership proof=profileBeforeEffect;
            if(proof==null||proof.windowId!=state.windowId)throw new ProfileOwnershipViolation("new search final actual profile proof missing");
            // No new ownership proof or refreshed timestamp; the existing broker/lease check may block.
            session.background.requireProfileWindow(proof,proof.windowId,proof.taskId,SystemClock.elapsedRealtime());
        }
        void requireFinalProfileClock(){
            WindowOwnership proof=profileBeforeEffect;
            if(proof==null||proof.windowId!=state.windowId)throw new ProfileOwnershipViolation("new search final profile clock has no actual proof");
            // Pure value check after every possibly blocking fence and final event check.
            proof.requireMatches(session.background.profileTarget(),session.background.generation,session.background.displayId(),
                    proof.windowId,proof.taskId,SystemClock.elapsedRealtime());
        }
    }
    void performNativeOpenSearch(final String taskId,final NativeSearchSession.Attempt attempt,final Cancellation cancel,
            final NativeSearchSession.ActionCallback callback){
        if(attempt==null||cancel==null||callback==null||!taskId.equals(attempt.session.taskId))
            throw new IllegalArgumentException("actual typed native search Attempt required");
        final QualificationScopeConfig.Bound captured=scopeFor(taskId);
        final NativeSearchSession session=attempt.session;
        boolean posted=main.post(new Runnable(){public void run(){
            SearchActionWork admitted=null;
            try{
                if(!nativeSearchSessionCurrent(session,captured)||activeObservation!=null||activeNativeSearchObservation!=null
                        ||observationReadWorkPending()||capturePending||actionWorkPending()||nativeCancellationWorkPending()||cancel.isCancelled())
                    throw new IllegalStateException("typed search dispatch does not own the current idle read/lease");
                attempt.requireLive(SystemClock.elapsedRealtime());
                final SearchActionWork work=new SearchActionWork(attempt,captured,cancel);
                if(!actionSlot.acquire(work.state))throw new IllegalStateException("previous action has not physically drained");
                activeSearchAction=work;lastActionExecution=work.state;admitted=work;
                try{registerNativeSearchActionTracker(work);}
                catch(RuntimeException definitelyUnsubmitted){
                    // Registration precedes execute; this work provably owns no worker.
                    work.state.retire("queue_rejected");work.marker(work.state.drained());
                    if(activeSearchAction==work)activeSearchAction=null;actionSlot.release(work.state);
                    throw definitelyUnsubmitted;
                }
                try{actionIo.execute(new Runnable(){public void run(){runNativeOpenSearch(work,callback);}});}
                catch(java.util.concurrent.RejectedExecutionException rejected){
                    work.state.retire("queue_rejected");work.marker(work.state.drained());
                    if(activeSearchAction==work)activeSearchAction=null;actionSlot.release(work.state);clearNativeSearchActionTracker(work);
                    boolean current=work.currentLease()&&lastActionExecution==work.state;
                    work.state.publish(cancel.isCancelled(),current);
                    callback.onResult(bindNativeSearchOutcome(work,new ActionOutcome(false,false,false,"搜索动作队列未接受请求"),current));
                }catch(RuntimeException uncertain){
                    // A runtime submit exception cannot prove no worker/effect started.
                    work.state.retire("controller_abandoned");
                }
            }catch(Exception refused){
                if(admitted!=null)admitted.state.retire("controller_abandoned");
                boolean current=nativeSearchSessionCurrent(session,captured)&&!cancel.isCancelled();
                ActionOutcome result=new ActionOutcome(false,false,refused instanceof StaleObservation,"搜索意图未派发："+message(refused));
                callback.onResult(result.withScope(callbackScopeEvidence(taskId,captured,current,cancel.isCancelled()))
                        .withAuthorization(callbackAuthorizationEvidence(session.authorization,current,cancel.isCancelled()))
                        .withBackground(session.background.evidence()));
            }
        }});
        if(!posted){
            boolean current=nativeSearchSessionCurrent(session,captured)&&!cancel.isCancelled();
            callback.onResult(new ActionOutcome(false,false,false,"搜索动作主线程没有接受请求")
                    .withScope(callbackScopeEvidence(taskId,captured,current,cancel.isCancelled()))
                    .withAuthorization(callbackAuthorizationEvidence(session.authorization,current,cancel.isCancelled()))
                    .withBackground(session.background.evidence()));
        }
    }
    private void runNativeOpenSearch(final SearchActionWork work,final NativeSearchSession.ActionCallback callback){
        ActionOutcome result;
        try{
            work.phase("worker_started");result=executeNativeOpenSearch(work);
        }catch(Exception failure){
            result=new ActionOutcome(false,work.platformCallInvoked,failure instanceof StaleObservation,
                    "搜索导航未得到完整确认；不重试："+message(failure));
        }finally{
            sealNativeSearchExecutionEvidence(work);
            // C owns all of its references; D and temporary ancestors close in their own finally blocks.
            Graph owned=work.currentGraph;work.currentGraph=null;
            if(owned!=null)owned.close();work.marker(work.state.drained());
            if(activeSearchAction==work)activeSearchAction=null;actionSlot.release(work.state);
        }
        final ActionOutcome computed=result;
        if(work.hasNoEffectReplanFence()){
            try{
                actionIo.execute(new Runnable(){public void run(){
                    // This serial marker runs after the complete old worker stack returned.
                    work.replanDrainMarkerElapsed=SystemClock.elapsedRealtime();work.replanDrainMarkerCompleted=true;
                    publishNativeSearchOutcome(work,callback,computed);
                }});
            }catch(java.util.concurrent.RejectedExecutionException rejected){
                publishNativeSearchOutcome(work,callback,computed);
            }catch(RuntimeException uncertain){
                work.replanDrainUncertain=true;publishNativeSearchOutcome(work,callback,computed);
            }
        }else publishNativeSearchOutcome(work,callback,computed);
    }
    private void requireNativeSearchNoEffectFacts(SearchActionWork work,ActionOutcome outcome){
        Map<String,Object> execution=work.state.evidence();
        boolean originalPairRecorded=work.bannerRefusal==null?work.roleProof!=null:
                work.roleProof==null&&work.attempt.ownsBannerRefusal(work.bannerRefusal)
                        &&work.bannerRefusal.first==work.currentSnapshot&&work.bannerRefusal.second==work.latestSnapshot;
        if(!work.hasNoEffectReplanFence()||work.noEffectRejectionWatermark()==null||!originalPairRecorded||work.currentGraph!=null
                ||!work.currentNodeIdentityChecked||work.ancestorChainChecked||work.windowsChecked
                ||work.platformCallInvoked||work.state.effectEntered()||!work.state.isDrained()||work.state.retired()
                ||!work.replanDrainMarkerCompleted||work.replanDrainUncertain||work.sealedDiagnostic==null
                ||!NativeAppEvidence.sha(work.sealedDiagnosticSha)
                ||work.replanDrainMarkerElapsed<((Number)execution.get("worker_drained_elapsed_ms")).longValue()
                ||outcome==null||outcome.accepted||outcome.dispatched||!outcome.stale
                ||!Boolean.FALSE.equals(execution.get("effect_returned"))||execution.get("api_accepted")!=null
                ||!Boolean.TRUE.equals(execution.get("callback_published"))
                ||!Boolean.TRUE.equals(execution.get("callback_authority_current")))
            throw new IllegalStateException("actual unclaimed post-D worker/drain facts required");
    }
    private void publishNativeSearchOutcome(final SearchActionWork work,final NativeSearchSession.ActionCallback callback,final ActionOutcome computed){
        if(!work.callbackQueued.compareAndSet(false,true))return;
        boolean posted=main.post(new Runnable(){public void run(){
            // A newer action may acquire the drained slot before this callback runs.
            boolean current=work.currentLease()&&lastActionExecution==work.state;
            boolean allowed=work.state.publish(work.cancel.isCancelled(),current);
            ActionOutcome delivered=allowed?computed:new ActionOutcome(false,computed.dispatched,computed.stale,
                    "搜索动作回执已退休；保留真实效果，不重新派发");
            ActionOutcome bound=bindNativeSearchOutcome(work,delivered,current);
            NativeSearchNoEffectReplanProof proof=null;
            if(allowed&&work.hasNoEffectReplanFence()){
                try{
                    long now=SystemClock.elapsedRealtime();work.session.requireNoEffectCandidate(work.attempt,now);
                    requireNativeSearchNoEffectFacts(work,bound);
                    synchronized(nativeSearchEventLock){
                        if(nativeSearchTrackedAction!=work)throw new IllegalStateException("search event tracker no longer current");
                        requireNativeSearchPairEvents(work.pairCompleted,work.events.mark());
                        if(!work.events.mark().monotonicSince(work.noEffectRejectionWatermark()))
                            throw new IllegalStateException("search refusal watermark regressed");
                        proof=new NativeSearchNoEffectReplanProof(HeptaAccessibilityService.this,work,bound,now);
                    }
                    proof.requireOriginal(work.session,work.attempt,SystemClock.elapsedRealtime(),false);
                }catch(RuntimeException unavailable){proof=null;}
            }
            if(proof==null){clearNativeSearchActionTracker(work);callback.onResult(bound);}
            else callback.onNoEffectReplanAvailable(bound,proof);
        }});
        if(!posted){work.state.retire("controller_abandoned");clearNativeSearchActionTracker(work);}
    }
    private ActionOutcome bindNativeSearchOutcome(SearchActionWork work,ActionOutcome outcome,boolean current){
        boolean stopped=work.cancel.isCancelled();
        return outcome.withScope(callbackScopeEvidence(work.session.taskId,work.scope,current,stopped))
                .withAuthorization(callbackAuthorizationEvidence(work.session.authorization,current,stopped))
                .withBackground(work.session.background.evidence()).withActionExecution(nativeSearchExecutionEvidence(work));
    }
    private static JSONObject nativeSearchExecutionEvidence(SearchActionWork work){
        JSONObject out=new JSONObject(work.state.evidence());
        try{out.put("queued_clock_sampling","native_search_attempt_reservation_before_main_post");
            if(work.sealedDiagnostic!=null)out.put("native_search_execution",work.sealedDiagnostic);}
        catch(Exception unavailable){/* A diagnostic never authorizes delivery. */}
        return out;
    }
    /** Full pure census encoding belongs to the worker, before it is marked drained. */
    private static void sealNativeSearchExecutionEvidence(SearchActionWork work){
        try{
            Map<String,Object> proof=new LinkedHashMap<String,Object>();proof.put("schema","hepta.native-search-current-execution.v1");
            proof.put("action",NativeSearchDecision.ACTION);proof.put("planning_receipt_sha256",work.attempt.offer.planning.receiptSha256);
            proof.put("attempt",work.attempt.evidence());
            proof.put("current_C",work.currentSnapshot==null?null:NativeAppEvidence.immutableMap(NativeSearchPlanning.snapshot(work.currentSnapshot)));
            proof.put("latest_D",work.latestSnapshot==null?null:NativeAppEvidence.immutableMap(NativeSearchPlanning.snapshot(work.latestSnapshot)));
            proof.put("current_C_read_attempts",work.currentReadAttempts);proof.put("current_C_resample_limit",NATIVE_SEARCH_CURRENT_C_READ_LIMIT-1);
            proof.put("original_attempt_deadline_elapsed_ms",work.attempt.deadlineElapsed);
            proof.put("role_comparison",work.roleProof);proof.put("pair_start_watermark",work.pairStart==null?null:work.pairStart.evidence());
            proof.put("D_completed_watermark",work.pairCompleted==null?null:work.pairCompleted.evidence());
            proof.put("before_effect_watermark",work.effectWatermark==null?null:work.effectWatermark.evidence());
            proof.put("D_read_returned_elapsed_ms",work.latestReadReturnedElapsed<0?null:Long.valueOf(work.latestReadReturnedElapsed));
            proof.put("D_snapshot_completed_elapsed_ms",work.latestSnapshotCompletedElapsed<0?null:Long.valueOf(work.latestSnapshotCompletedElapsed));
            proof.put("role_compared_elapsed_ms",work.roleComparedElapsed<0?null:Long.valueOf(work.roleComparedElapsed));
            proof.put("first_final_event_check_elapsed_ms",work.firstFinalEventsElapsed<0?null:Long.valueOf(work.firstFinalEventsElapsed));
            proof.put("first_final_event_rejection_watermark",work.firstRejectedWatermark==null?null:work.firstRejectedWatermark.evidence());
            proof.put("typed_post_D_first_fence_rejected",work.firstPostDEventRejected);
            proof.put("overlapping_blank_banner_pair_rejected",work.bannerRefusal!=null);
            proof.put("after_target_refresh_event_check_elapsed_ms",work.afterTargetRefreshEventsElapsed<0?null:Long.valueOf(work.afterTargetRefreshEventsElapsed));
            proof.put("after_target_refresh_event_rejection_watermark",work.afterTargetRefreshRejectedWatermark==null?null:work.afterTargetRefreshRejectedWatermark.evidence());
            proof.put("typed_post_D_after_target_refresh_fence_rejected",work.typedAfterTargetRefreshPostDEventRejected);
            proof.put("final_preclaim_event_check_elapsed_ms",work.finalPreclaimEventsElapsed<0?null:Long.valueOf(work.finalPreclaimEventsElapsed));
            proof.put("final_preclaim_rejection_watermark",work.finalPreclaimRejectedWatermark==null?null:work.finalPreclaimRejectedWatermark.evidence());
            proof.put("typed_final_preclaim_content_rejected",work.typedFinalPreclaimContentRejected);
            proof.put("complete_census_resamples",work.finalCensusResamples);proof.put("complete_census_resample_limit",1);
            proof.put("discarded_final_censuses",work.discardedFinalCensuses);
            proof.put("original_chain_deadline_elapsed_ms",work.session.chainDeadlineElapsed);
            proof.put("original_reference_begins_at_current_C",true);proof.put("same_C_D_android_node",work.currentNodeIdentityChecked);
            proof.put("original_C_node_and_actual_ancestor_chain",work.ancestorChainChecked);proof.put("reported_windows_before_after_equal",work.windowsChecked);
            proof.put("live_profile_before_effect",work.profileBeforeEffect==null?null:work.profileBeforeEffect.evidence());
            proof.put("platform_call_invoked",work.platformCallInvoked);proof.put("coordinates_used_for_input",false);
            proof.put("old_click_replayed",false);proof.put("full_tree_stable_claimed",false);proof.put("query_or_price_verified",false);
            JSONObject value=NativeSearchPlanning.json(proof);byte[] encoded=value.toString().getBytes(StandardCharsets.UTF_8);
            if(encoded.length<=NativeSearchPlanning.MAX_BYTES){work.sealedDiagnostic=value;work.sealedDiagnosticSha=sha(encoded);}
        }catch(Exception unavailable){/* Missing diagnostic evidence never grants an effect or permits a retry. */}
    }
    /** Only a typed unavailable descendant may restart an incomplete C read.
     * readGraph has already closed its partial Graph and recycled its queue.
     * Every sample is a new complete graph; no partial node may become C.
     * The original event interval and reserved eight-second deadline never move.
     * Eight total reads also bound the ledger and a rapidly failing sampler;
     * this defensive count does not grant more time or another action. */
    private Graph readNativeSearchCurrentGraph(SearchActionWork work){
        for(int ordinal=work.currentReadAttempts.size()+1;;ordinal++){
            if(ordinal>NATIVE_SEARCH_CURRENT_C_READ_LIMIT)
                throw new StaleObservation("new search original Attempt current C read budget is exhausted");
            work.phase("graph_read");work.attempt.requireUnvalidatedRead(SystemClock.elapsedRealtime());
            if(work.currentGraph!=null||work.currentSnapshot!=null||work.latestSnapshot!=null||work.platformCallInvoked)
                throw new IllegalStateException("new search current C read cannot reuse a prior graph or effect");
            Map<String,Object> read=new LinkedHashMap<String,Object>();read.put("ordinal",ordinal);
            read.put("complete_census_round",work.finalCensusResamples+1);
            read.put("started_elapsed_ms",SystemClock.elapsedRealtime());read.put("completed",false);
            read.put("fresh_complete_read_next",false);work.currentReadAttempts.add(read);
            try{
                Graph graph=readGraph(work.budget(),work.session.background);read.put("completed",true);return graph;
            }catch(RuntimeException failure){
                boolean unavailableChild=failure instanceof StaleObservation&&((StaleObservation)failure).backgroundChildUnavailable;
                read.put("background_child_unavailable",unavailableChild);read.put("failure",message(failure));
                read.put("partial_graph_discarded",unavailableChild);
                if(!unavailableChild||ordinal>=NATIVE_SEARCH_CURRENT_C_READ_LIMIT)throw failure;
                work.check();work.attempt.requireUnvalidatedRead(SystemClock.elapsedRealtime());
                // A replacement sample cannot hide an unknown, boundary or untyped event.
                requireNativeSearchPairEvents(work.pairStart,work.events.mark());
                read.put("fresh_complete_read_next",true);
            }finally{read.put("ended_elapsed_ms",SystemClock.elapsedRealtime());}
        }
    }
    private ActionOutcome executeNativeOpenSearch(SearchActionWork work)throws Exception{
        try{
            for(;;){
                try{return executeNativeOpenSearchCensus(work);}
                catch(NativeSearchFinalCensusChanged changed){
                    // The private proof permits at most one complete replacement pair.
                    // This stack keeps the same slot, tracker, model run and old deadline.
                    work.discardFinalCensusForResample(changed.proof);
                }
            }
        }finally{work.pendingFinalCensusResample=null;}
    }
    private ActionOutcome executeNativeOpenSearchCensus(SearchActionWork work)throws Exception{
        work.phase("scope_read");work.scope.verifyUnchanged();
        QualificationScope.require(!work.scope.restricted(),"typed search cannot extend a qualification scope");
        requireTaskAuthorization(work.session.taskId,work.session.authorization);work.attempt.verifyInstalled();work.check();
        Graph fresh=null;
        try{
            if(work.pairStart==null)work.pairStart=work.events.mark();
            else requireNativeSearchPairEvents(work.pairStart,work.events.mark());
            work.currentGraph=readNativeSearchCurrentGraph(work);
            NativeActionSnapshotCheck.Snapshot current=nativeSearchSnapshot(work.currentGraph,work.session,work.attempt.offer.planning.id,work.attempt.startedElapsed);
            work.currentSnapshot=current;
            NativeSearchRole currentRole=NativeSearchRole.compare(current,current);work.attempt.offer.planning.role.requireSameRole(currentRole);
            NodeRef original=nativeSearchNode(work.currentGraph,currentRole.targetPath);
            if(!NativeAppEvidence.hash(original.signature).equals(current.node(currentRole.targetPath).v.get("ref_signature_sha256")))
                throw new StaleObservation("new search C reference does not match its complete census");
            work.attempt.verifyInstalled();work.check();work.phase("graph_read");fresh=readGraph(work.budget(),work.session.background);
            work.pairCompleted=work.events.mark();work.latestReadReturnedElapsed=SystemClock.elapsedRealtime();
            NativeActionSnapshotCheck.Snapshot latest=nativeSearchSnapshot(fresh,work.session,work.attempt.offer.planning.id,work.attempt.startedElapsed);
            work.latestSnapshot=latest;work.latestSnapshotCompletedElapsed=SystemClock.elapsedRealtime();
            requireNativeSearchPairEvents(work.pairStart,work.pairCompleted);
            final NativeSearchRole revalidated;
            try{revalidated=work.attempt.revalidate(current,latest,SystemClock.elapsedRealtime());}
            catch(NativeSearchRole.RejectedBannerMotion refused){
                work.check();
                NodeRef latestTarget=nativeSearchNode(fresh,currentRole.targetPath);
                if(!work.attempt.ownsBannerRefusal(refused)||refused.first!=current||refused.second!=latest
                        ||!original.node.equals(latestTarget.node)||!original.signature.equals(latestTarget.signature))
                    throw new StaleObservation("ambiguous search carousel and changed current target");
                synchronized(nativeSearchEventLock){
                    NativeSearchPlanning.EventMark observed=work.events.mark();
                    requireNativeSearchPairEvents(work.pairCompleted,observed);
                    if(nativeSearchTrackedAction!=work||activeSearchAction!=work||work.platformCallInvoked||work.state.effectEntered())
                        throw new StaleObservation("ambiguous search carousel after action lease changed");
                    work.currentNodeIdentityChecked=true;work.bannerRefusal=refused;work.bannerRefusalWatermark=observed;
                }
                throw new StaleObservation(refused.getMessage());
            }
            work.roleProof=revalidated.evidence();work.roleComparedElapsed=SystemClock.elapsedRealtime();
            NodeRef same=nativeSearchNode(fresh,revalidated.targetPath);
            if(!original.node.equals(same.node)||!NativeAppEvidence.hash(same.signature).equals(latest.node(revalidated.targetPath).v.get("ref_signature_sha256")))
                throw new StaleObservation("new search current C node was replaced before D");
            work.currentNodeIdentityChecked=true;work.requireFirstFinalEvents();
            Map<String,Object> before=readNativeActionWindows(fresh,work.budget());
            if(!fresh.nativeActionWindows.equals(before))throw new StaleObservation("new search complete D window set changed");
            refreshNativeSearchTargetChain(work,original,revalidated.targetPath,latest,fresh);
            work.ancestorChainChecked=true;work.requireFinalEvents();
            Map<String,Object> after=readNativeActionWindows(fresh,work.budget());
            if(!before.equals(after))throw new StaleObservation("new search final reported windows changed");
            work.windowsChecked=true;
            FrozenObservationWindow actual=readNativeSearchWindow(work.session,work.scope,work.budget());
            FrozenObservationWindow expected=frozenObservationWindow(fresh);
            if(expected==null||!expected.matches(actual))throw new StaleObservation("new search final actual window/profile differs from D");
            requireSameProfileWindow(fresh.profileWindow,actual.profileWindow);work.profileBeforeEffect=actual.profileWindow;
            work.session.background.requirePolicyBeforeEffect(work.boundedCancellation(),work.state.deadlineElapsed);
            work.scope.verifyUnchanged();requireTaskAuthorization(work.session.taskId,work.session.authorization);
            work.attempt.requireLive(SystemClock.elapsedRealtime());work.requireFinalPreclaimEvents(revalidated,fresh);work.requireFinalProfile();
            work.phase("attempt_journal");
            work.attempt.claim(SystemClock.elapsedRealtime());work.requireFinalEvents();
            work.marker(work.state.enterEffect(work.cancel.isCancelled(),work.currentLease()));work.check();work.requireFinalEvents();
            work.requireFinalProfile();work.requireFinalEvents();work.effectWatermark=work.events.mark();work.requireFinalEvents();
            work.requireFinalProfileClock();work.platformCallInvoked=true;
            boolean accepted=original.node.performAction(AccessibilityNodeInfo.ACTION_CLICK);
            work.marker(work.state.effectReturned(Boolean.valueOf(accepted)));
            // The single platform return is ready for the original worker drain and authority check.
            // Navigation is verified only by a separately owned, fresh AX observation.
            work.check();return new ActionOutcome(accepted,true,false,accepted?"搜索导航已接受；输入框与业务结果仍需新观察":"搜索导航未被接受；不重复派发");
        }finally{if(fresh!=null)fresh.close();}
    }
    private static void requireNativeSearchPairEvents(NativeSearchPlanning.EventMark before,NativeSearchPlanning.EventMark after){
        if(before==null||after==null||!after.monotonicSince(before)||after.unknown!=before.unknown
                ||after.boundary!=before.boundary||after.events-before.events!=after.content-before.content)
            throw new StaleObservation("new search current C/D interval includes an unknown, boundary or untyped event");
    }
    private static NodeRef nativeSearchNode(Graph graph,String path){
        NodeRef found=null;int count=0;
        for(PhoneObservation.Node row:graph.rows)if(path.equals(row.nativeTreePath)){
            found=graph.refs.get(row.id);count++;
        }
        if(count!=1||found==null)throw new StaleObservation("new search current role does not identify one retained actual node");
        return found;
    }
    private void requireNativeSearchNodeWindow(SearchActionWork work,Graph graph,AccessibilityNodeInfo node){
        work.check();if(!graph.packageName.equals(string(node.getPackageName()))||node.getWindowId()!=graph.windowId)
            throw new StaleObservation("new search original node moved to another package/window");
        AccessibilityWindowInfo window=node.getWindow();
        try{
            if(window==null||window.getId()!=graph.windowId||window.getDisplayId()!=graph.displayId
                    ||window.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION||graph.profileWindow==null
                    ||actualProfileAccessibilityTaskId(window)!=graph.profileWindow.taskId)
                throw new ProfileOwnershipViolation("new search original node is no longer in the actual profile leaf");
            work.session.background.requireActive();work.check();
        }finally{if(window!=null)window.recycle();}
    }
    private boolean refreshNativeSearchNode(SearchActionWork work,AccessibilityNodeInfo node){
        work.phase("node_refresh");boolean refreshed=node.refresh();work.check();return refreshed;
    }
    /** Refreshes C's exact reference and actual parent/child identities against complete D. */
    private void refreshNativeSearchTargetChain(SearchActionWork work,NodeRef original,String targetPath,
            NativeActionSnapshotCheck.Snapshot snapshot,Graph latest)throws Exception{
        if(original==null)throw new StaleObservation("new search current C reference missing");
        List<AccessibilityNodeInfo> temporary=new ArrayList<AccessibilityNodeInfo>();
        AccessibilityNodeInfo cursor=original.node;String path=targetPath;Rect targetBounds=new Rect();cursor.getBoundsInScreen(targetBounds);
        try{
            for(int depth=0;depth<64;depth++){
                NativeActionSnapshotCheck.Node expected=snapshot.node(path);work.check();
                if(!refreshNativeSearchNode(work,cursor)||!cursor.isVisibleToUser()||!cursor.isEnabled()||cursor.isPassword())
                    throw new StaleObservation("new search original target/ancestor unavailable");
                requireNativeSearchNodeWindow(work,latest,cursor);
                Rect bounds=new Rect();cursor.getBoundsInScreen(bounds);
                if(!bounds.contains(targetBounds))throw new StaleObservation("new search actual ancestor no longer contains the target");
                NativeActionSnapshotCheck.Node actual=snapshotNativeActionNode(cursor,path,expected.parent,null,null);
                Map<String,Object> before=new java.util.TreeMap<String,Object>(expected.v),now=new java.util.TreeMap<String,Object>(actual.v);
                before.remove("label");before.remove("ref_signature_sha256");now.remove("label");now.remove("ref_signature_sha256");
                if(!before.equals(now))throw new StaleObservation("new search target/ancestor differs from the latest complete D");
                Object signature=expected.v.get("ref_signature_sha256");
                if(signature!=null){
                    ObservedChildText.Result children=observedChildText(cursor,true,work.budget());
                    if(!signature.equals(NativeAppEvidence.hash(nodeSignature(cursor,children))))
                        throw new StaleObservation("new search target/ancestor full signature changed after D");
                    if(path.equals(targetPath)){
                        PersistentActionPolicy.Decision policy=PersistentActionPolicy.evaluate(string(cursor.getText()),string(cursor.getContentDescription()),children.text,cursor.isEditable());
                        if(!policy.allowed)throw new IllegalArgumentException(policy.reasonCode+": "+policy.detail);
                    }
                }
                AccessibilityNodeInfo parent=cursor.getParent();if(parent!=null)temporary.add(parent);work.check();
                if("0".equals(path)){
                    if(parent!=null||!latest.windowMetadata.bindFreshness("").equals(readWindowMetadata(cursor,bounds,latest.windowId,latest.displayId).bindFreshness("")))
                        throw new StaleObservation("new search current root/window metadata changed");
                    work.requireAfterTargetRefreshEvents();return;
                }
                int slash=path.lastIndexOf('/'),index=Integer.parseInt(path.substring(slash+1));
                if(parent==null||!refreshNativeSearchNode(work,parent)||index>=parent.getChildCount()||!expected.parent.equals(string(parent.getClassName())))
                    throw new StaleObservation("new search actual parent relation changed");
                AccessibilityNodeInfo child=parent.getChild(index);if(child!=null)temporary.add(child);work.check();
                if(child==null||!refreshNativeSearchNode(work,child)||!child.equals(cursor))
                    throw new StaleObservation("new search actual child identity changed");
                cursor=parent;path=path.substring(0,slash);
            }
            throw new StaleObservation("new search actual ancestor budget exhausted");
        }finally{for(AccessibilityNodeInfo node:temporary)node.recycle();}
    }

    private final class ActionWork {
        final ActionExecutionState state;final PhoneObservation expected;final Graph graph;final Cancellation cancel;
        final QualificationScopeConfig.Bound scope;final TaskAuthorization.Gate authorization;final BackgroundSession background;
        final WebRegionNativeBridge nativeRegion;
        String diagnosticFreshness;
        final NativeAppSession.ActionGuard nativeGuard;
        boolean nativeActionRevalidated;String nativeActionProof,nativeActionRejection;
        Map<String,Object> queryCensusRetry;
        WindowOwnership profileDispatchProof;
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
        GraphBudget budget(){return new GraphBudget(){public void check(){ActionWork.this.check();}
            public Cancellation cancellation(){return cancel;}public long deadline(){return state.deadlineElapsed;}};}
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
        if(work.queryCensusRetry!=null)try{value.put("query_census_retry",new JSONObject(work.queryCensusRetry));}
        catch(Exception unavailable){/* This read diagnostic cannot authorize an effect. */}
        if(work.nativeActionRejection!=null)try{value.put("native_action_rejection_census",new JSONObject(work.nativeActionRejection));}
        catch(Exception unavailable){/* Preserve the original refusal and execution lifecycle. */}
        if(work.nativeActionProof!=null)try{value.put("native_action_revalidation",new JSONObject(work.nativeActionProof));}
        catch(Exception unavailable){/* The original dispatch/retirement evidence remains authoritative. */}
        if(work.profileDispatchProof!=null)try{value.put("live_profile_before_effect",new JSONObject(work.profileDispatchProof.evidence()));}
        catch(Exception unavailable){/* Metadata cannot authorize or repeat an effect. */}
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
    /** Last worker fence before any effect entry; no stale action is replayed. */
    private void requireLiveProfileBeforeEffect(ActionWork work){
        if(work.background==null||work.background.profileTarget()==null)return;
        actionCheck(work);requireHistoricalProfileWindow(work.background,work.expected);
        AccessibilityNodeInfo root=selectedRoot(work.background,work.budget());
        if(root==null)throw new ProfileOwnershipViolation("profile 派发前实际窗口缺失");
        try{
            WindowOwnership actual=readProfileWindow(root,work.background,work.budget());
            requireSameProfileOwner(work.expected.profileWindow,actual);
            if(actual.windowId!=work.expected.windowId)
                throw new StaleObservation("profile 同任务窗口已换代，未派发旧动作");
            work.profileDispatchProof=actual;actionCheck(work);
        }finally{root.recycle();}
    }
    private void enterActionEffect(ActionWork work){if(work!=null){
        requireLiveProfileBeforeEffect(work);
        if(work.background!=null)work.background.requirePolicyBeforeEffect(actionCancellation(work,work.cancel),work.state.deadlineElapsed);
        actionCheck(work);work.enterEffect();
    }}
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
        requireHistoricalProfileWindow(background,frame);
        requireSameProfileWindow(original.profileWindow,frame.profileWindow);
        requireSameProfileWindow(original.profileWindow,work.graph.profileWindow);
        if(guard.authorization!=work.authorization||background.selection!=guard.selection
                ||work.expected!=frame||!task.equals(work.state.taskId)||guard.deadline!=work.state.deadlineElapsed
                ||guard.issued>work.state.queuedElapsed
                ||background.selection.taskTarget!=guard.target||guard.target.nativeGoal!=guard.goal
                ||!task.equals(original.taskId)||!task.equals(background.taskId)||!original.observationId.equals(frame.id)
                ||!original.stateSha.equals(frame.treeSha256)||!original.treeSha.equals(frame.state.appTreeSha256)
                ||!original.sameCapture(frame.capture,frame.screenshotSha256)||original.capturedElapsedMs!=frame.capturedElapsedMillis
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
    /** Read-only fallback for one already-observed managed Ctrip form.
     * Complete raw censuses, never diagnostic summaries, supply both sides.
     * No ActionGuard/Intent, model action, query history or NodeRef is minted.
     */
    private Map<String,Object> nativeCtripFormPair(ObservationRequest request,CaptureIdentity identity,Graph after){
        boolean postEffect=request.postEffectController!=null;
        if(request.initialController!=null||request.readAuthorization==null||request.readAuthorization!=taskAuthorization
                ||request.background==null||!identity.nativeRecheck||identity.frozenWindow==null
                ||request.captured==null||after==null||identity.unknownEvents!=0||request.unknownEvents!=0
                ||!nativeObservationRecheckAllowed(request,request.captured)||!nativeObservationRecheckAllowed(request,after)
                ||!identity.frozenWindow.matches(frozenObservationWindow(after)))return null;
        if(postEffect){
            if(request.readBefore!=null||request.readIdentity!=null||request.retrySubmission!=null
                    ||request.postEffectIdentityRejected||!postEffectObservationOwner(request)
                    ||request.postEffectIdentity!=null&&(!request.postEffectIdentity.matches(request.captured)
                    ||!request.postEffectIdentity.matches(after)))return null;
        }else if(request.readBefore==null||request.readBefore!=current||request.readIdentity==null||request.readRecoveryRejected
                ||!request.readIdentity.matches(request.captured)||!request.readIdentity.matches(after))return null;
        ProfileTarget target=request.background.profileTarget();
        BackgroundTaskTarget task=request.background.selection.taskTarget;
        if(target==null||!NativeCtripFlightPage.PACKAGE.equals(target.packageName)
                ||target.versionCode!=NativeCtripFlightPage.VERSION_CODE
                ||!NativeCtripFlightPage.BASE_APK_SHA256.equals(target.apkHashes.get("base"))
                ||task==null||!NativeCtripFlightPage.supported(task.nativeGoal))return null;
        requireObservationWork(request);
        long now=SystemClock.elapsedRealtime();
        if(identity.graphStartedAt<request.started||identity.graphCompletedAt<identity.graphStartedAt
                ||identity.graphCompletedAt>identity.capturedAt||after.readStartedElapsedMs<identity.capturedAt
                ||after.readCompletedElapsedMs<after.readStartedElapsedMs||after.readCompletedElapsedMs>now)return null;
        try{
            Map<String,Object> proof=NativeCtripFormObservation.compare(
                    nativeCtripFormSnapshot(request,request.captured,target),nativeCtripFormSnapshot(request,after,target));
            if(postEffect){
                Map<String,Object> bound=new java.util.LinkedHashMap<String,Object>(proof);
                bound.put("entered_open_read_permit",request.postEffectPermit.evidence());
                proof=java.util.Collections.unmodifiableMap(bound);
            }
            if(new JSONObject(proof).toString().getBytes(StandardCharsets.UTF_8).length>262144)return null;
            requireObservationWork(request);
            return postEffect&&(!postEffectObservationOwner(request)||request.postEffectIdentityRejected)?null:proof;
        }catch(IllegalArgumentException unclassified){return null;}
    }
    /** Actual ownership and complete raw rows are copied; expected facts never
     * fill a missing census. The old observation id is lineage, not a new frame. */
    private NativeActionSnapshotCheck.Snapshot nativeCtripFormSnapshot(ObservationRequest request,Graph graph,ProfileTarget target){
        PhoneObservation.CollectionStats stats=graph.collectionStats;
        BackgroundTaskTarget task=request.background.selection.taskTarget;
        final String actualSelectionSha;
        try{actualSelectionSha=NativeAppObservation.selectionSha(request.background.selection);}
        catch(Exception unavailable){throw new IllegalArgumentException("native form selection evidence unavailable",unavailable);}
        if(graph.nativeActionNodes==null||graph.nativeActionWindows==null||graph.truncated||stats==null||stats.truncated()
                ||graph.state==null||graph.state.imeVisibility!=ImeVisibility.HIDDEN||graph.windowMetadata==null
                ||graph.profileWindow==null||!request.taskId.equals(graph.nativeActionTaskId)
                ||!taskAuthorization.authorization.sha256.equals(graph.nativeActionAuthorizationSha)
                ||!actualSelectionSha.equals(graph.nativeActionSelectionSha)
                ||!task.targetSha256.equals(graph.nativeActionTargetSha)||!task.nativeGoal.contractSha256.equals(graph.nativeActionGoalSha)
                ||stats.childSlotsOmitted>Integer.MAX_VALUE||graph.nativeActionCapturedAt<request.started)
            throw new IllegalArgumentException("complete current read-only native census required");
        NativeAppEvidence.requireProfileTarget(target,graph.profileWindow);
        Map<String,Object> env=new java.util.TreeMap<String,Object>();
        env.put("task_id",graph.nativeActionTaskId);env.put("owner_sha256",graph.backgroundOwnerSha);
        env.put("target_sha256",graph.nativeActionTargetSha);env.put("authorization_sha256",graph.nativeActionAuthorizationSha);
        env.put("selection_sha256",graph.nativeActionSelectionSha);env.put("installed_set_sha256",target.apkSetSha256);
        env.put("goal_sha256",graph.nativeActionGoalSha);env.put("background_generation",graph.backgroundGeneration);
        env.put("origin_observation_id",request.postEffectController==null?request.readBefore.id:
                request.postEffectPermit.originalObservationId());
        env.putAll(NativeAppEvidence.profileActionIdentity(graph.profileWindow));
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
        requireSameProfileWindow(frame.profileWindow,graph.profileWindow);
        Map<String,Object> env=new java.util.TreeMap<String,Object>(guard.identity);
        // The fresh envelope copies actual graph ownership, never expected profile facts.
        if(graph.profileWindow!=null)env.putAll(NativeAppEvidence.profileActionIdentity(graph.profileWindow));
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
    private static boolean nativeSearchEntryGuard(ActionWork work){
        return work!=null&&work.nativeGuard!=null&&NativeActionSnapshotCheck.SEARCH.equals(work.nativeGuard.purpose)
                &&NativeAppGoal.XIAOMI_PACKAGE.equals(work.nativeGuard.goal.packageName);
    }
    /** Equal-tree Ctrip OPEN still needs the existing full final checker and
     * its real one-use claim before effect. That claim is also the prerequisite
     * for the unchanged Controller close-and-seal post-effect read handoff. */
    private static boolean nativeFlightOpenGuard(ActionWork work){
        return work!=null&&work.nativeGuard!=null&&NativeActionSnapshotCheck.OPEN.equals(work.nativeGuard.purpose)
                &&NativeCtripFlightPage.supported(work.nativeGuard.goal);
    }
    /** Read-only precheck deferral. No reference, action, label or observation is
     * replaced and no signature is declared current. This exact private SEARCH
     * guard must still pass finalNativeActionCheck even if the tree is equal. */
    private boolean deferNativeSearchEntrySignature(String task,PhoneObservation frame,ActionDecision action,
            AccessibilityNodeInfo node,ActionWork work)throws Exception{
        if(!nativeSearchEntryGuard(work)||scopeFor(task).config!=null)return false;
        requireNativeActionGuard(task,frame,action,work);
        NodeRef original=work.graph.refs.get(action.nodeId);NativeAppSession.ActionGuard guard=work.nativeGuard;
        if(original==null||original.node!=node||!original.appTreeSignature.equals(guard.targetNode.signature))return false;
        NativeActionSnapshotCheck.Snapshot snapshot=nativeActionSnapshot(work.graph,guard);
        NativeActionSnapshotCheck.Node expected=snapshot.node(guard.targetNode.path);
        NativeActionSnapshotCheck.Node live=snapshotNativeActionNode(node,expected.path,expected.parent,null,null);
        return NativeActionSnapshotCheck.searchEntryOwnFactsForFullRecheck(guard.intent(original.signature),snapshot,live);
    }
    private Map<String,Object> compareNativeAction(String task,PhoneObservation frame,ActionDecision action,Graph fresh,ActionWork work)throws Exception{
        requireNativeActionGuard(task,frame,action,work);NativeAppSession.ActionGuard guard=work.nativeGuard;
        Graph original=work.graph;
        if(!original.sameWindow(fresh))throw new StaleObservation("原生动作窗口变化");
        NodeRef before=original.refs.get(action.nodeId),after=null;
        for(PhoneObservation.Node row:fresh.rows)if(guard.targetNode.path.equals(row.nativeTreePath)){
            if(after!=null)throw new StaleObservation("原生同路径目标不唯一");after=fresh.refs.get(row.id);
        }
        if(before==null||after==null||!before.node.equals(after.node)
                ||(!nativeSearchEntryGuard(work)&&!before.signature.equals(after.signature))
                ||!before.appTreeSignature.equals(guard.targetNode.signature))
            throw new StaleObservation("原始NodeRef与同路径新节点不是同一目标");
        NativeActionSnapshotCheck.Snapshot oldSnapshot=nativeActionSnapshot(original,guard);
        NativeActionSnapshotCheck.Snapshot newSnapshot=nativeActionSnapshot(fresh,guard);
        NativeActionSnapshotCheck.Intent intent=guard.intent(before.signature);long comparedAt=SystemClock.elapsedRealtime();
        Map<String,Object> proof;
        try{proof=NativeActionSnapshotCheck.compare(intent,oldSnapshot,newSnapshot,comparedAt);}
        catch(IllegalArgumentException refusal){
            // Memory-only, bounded, same original worker. Missing diagnostics
            // never replace the predicate failure or permit an effect.
            if(work.nativeActionRejection==null)try{
                Map<String,Object> diagnostic=NativeActionSnapshotCheck.rejectionEvidence(intent,oldSnapshot,newSnapshot,comparedAt,
                        (String)work.state.evidence().get("operation_id"),guard.frame.screenshotSha,guard.frame.sourceRecordSha,refusal.getMessage(),guard.frame.capture);
                String raw=new JSONObject(diagnostic).toString();
                if(raw.getBytes(StandardCharsets.UTF_8).length<=NativeActionSnapshotCheck.MAX_REJECTION_DIAGNOSTIC_BYTES)
                    work.nativeActionRejection=raw;
            }catch(RuntimeException unavailable){/* The exact original refusal is still retained. */}
            // Only the comparator's explicit scene-currentness refusal is stale.
            // Malformed/authority/deadline failures keep their original hard failure.
            if(refusal instanceof NativeActionSnapshotCheck.CurrentnessChanged)
                throw new StaleObservation(refusal.getMessage());
            throw refusal;
        }
        actionCheck(work);return proof;
    }
    /** This budget belongs to one complete read inside a single original query Attempt. */
    private final class QueryGraphBudget implements GraphBudget {
        final ActionWork work;String currentPath;
        QueryGraphBudget(ActionWork work){this.work=work;}
        public void check(){work.check();}
        public Cancellation cancellation(){return work.cancel;}
        public long deadline(){return work.state.deadlineElapsed;}
    }
    private Graph readNativeActionGraph(String task,PhoneObservation frame,ActionDecision action,ActionWork work,boolean finalCheck)throws Exception{
        if(work==null||work.nativeGuard==null||frame.capture==null||!frame.capture.formHistory()
                ||!NativeActionSnapshotCheck.QUERY.equals(work.nativeGuard.purpose)||!NativeCtripFlightPage.supported(work.nativeGuard.goal))
            return readGraph(work==null?null:work.budget(),work==null?currentBackground():work.background);
        requireNativeActionGuard(task,frame,action,work);
        final QueryGraphBudget budget=new QueryGraphBudget(work);
        final String stage=finalCheck?"final_census":"validation_census";
        final long started=SystemClock.elapsedRealtime();
        try{return readGraph(budget,work.background);}
        catch(StaleObservation missing){
            if(!missing.backgroundChildUnavailable||budget.currentPath==null)throw missing;
            if(work.queryCensusRetry!=null){
                work.queryCensusRetry.put("later_failed_stage",stage);
                work.queryCensusRetry.put("later_failed_native_path",budget.currentPath);
                throw missing;
            }
            Map<String,Object> audit=new java.util.LinkedHashMap<String,Object>();
            work.queryCensusRetry=audit;
            audit.put("schema","hepta.ctrip-query-census-retry.v1");audit.put("failed_stage",stage);
            audit.put("failed_native_path",budget.currentPath);audit.put("reread_started",false);audit.put("reread_complete",false);
            audit.put("reused_partial_census",false);audit.put("action_replayed",false);
            actionCheck(work);requireNativeActionGuard(task,frame,action,work);work.nativeGuard.verifyInstalled();actionCheck(work);
            long now=SystemClock.elapsedRealtime();
            // Never renew the Attempt or start when even the last incomplete traversal's duration cannot fit.
            if(now<started||work.state.effectEntered()||now>=work.state.deadlineElapsed
                    ||work.state.deadlineElapsed-now<=now-started)throw missing;
            budget.currentPath=null;audit.put("reread_started",true);
            try{
                Graph full=readGraph(budget,work.background);
                audit.put("reread_complete",true);return full;
            }catch(StaleObservation again){
                if(again.backgroundChildUnavailable&&budget.currentPath!=null){
                    audit.put("later_failed_stage",stage);audit.put("later_failed_native_path",budget.currentPath);
                }
                throw again;
            }
        }
    }
    /** The final whole-census comparison includes every protected form field,
     * not just the clicked control. Later live checks cover the original target
     * and its actual parent/child chain; they do not claim an atomic UI. */
    private void finalNativeActionCheck(String task,PhoneObservation frame,ActionDecision action,ActionWork work)throws Exception{
        requireNativeActionGuard(task,frame,action,work);NativeAppSession.ActionGuard guard=work.nativeGuard;
        guard.verifyInstalled();actionCheck(work);
        Graph fresh=null;
        try{
            actionPhase(work,"graph_read");fresh=readNativeActionGraph(task,frame,action,work,true);
            Map<String,Object> proof=compareNativeAction(task,frame,action,fresh,work);
            Map<String,Object> windowsBefore=readNativeActionWindows(fresh,work.budget());
            if(!fresh.nativeActionWindows.equals(windowsBefore))throw new StaleObservation("完整复核后原生窗口集合变化");
            NativeActionSnapshotCheck.Snapshot checked=nativeActionSnapshot(nativeSearchEntryGuard(work)?fresh:work.graph,guard);
            refreshNativeActionTargetChain(work.background,frame,work.graph.refs.get(action.nodeId),guard.targetNode.path,checked,work);
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
                // The bound census retains the full derived signature: original
                // for ordinary purposes, the just-compared fresh one for SEARCH.
                before.remove("label");before.remove("ref_signature_sha256");now.remove("label");now.remove("ref_signature_sha256");
                if(!before.equals(now))throw new StaleObservation("原生目标祖先属性或选择状态变化");
                Object fullSignatureSha256=expected.v.get("ref_signature_sha256");
                if(fullSignatureSha256!=null){
                    ObservedChildText.Result children=observedChildText(cursor,true,work.budget());
                    if(!fullSignatureSha256.equals(NativeAppEvidence.hash(nodeSignature(cursor,children))))
                        throw new StaleObservation("原生目标祖先签名变化");
                    if(path.equals(targetPath)&&nativeSearchEntryGuard(work)){
                        PersistentActionPolicy.Decision policy=PersistentActionPolicy.evaluate(string(cursor.getText()),
                                string(cursor.getContentDescription()),children.text,cursor.isEditable());
                        if(!policy.allowed)throw new IllegalArgumentException(policy.reasonCode+": "+policy.detail);
                    }
                }
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
        if(locked(work.background))return "当前显示范围的锁状态或后台显示凭据不可用";
        try{requireBackgroundObservation(taskId,expected);}catch(Exception mismatch){return "后台观察无效："+message(mismatch);}
        if(expected!=current||graph==null||!expected.id.equals(action.observationId))return "stale:观察标识已失效";
        if(expected.capture!=null&&expected.capture.formHistory()&&!"wait".equals(action.action)&&!"done".equals(action.action)){
            if(work==null||work.nativeGuard==null||!"click".equals(action.action)
                    ||!(NativeActionSnapshotCheck.YEAR.equals(work.nativeGuard.purpose)
                    ||NativeActionSnapshotCheck.QUERY.equals(work.nativeGuard.purpose)))
                return "stale:历史表单只能经本次日期或查询原生Guard重新完整校验";
        }
        String bindingError=targetBindingError(expected,action,targets);if(bindingError!=null)return bindingError;
        long age=SystemClock.elapsedRealtime()-expected.capturedElapsedMillis;
        if(age<0||age>MAX_OBSERVATION_AGE_MS)return "stale:观察已过期";
        if(!"open".equals(action.action)&&!org.trillionnium.hepta.background.FixedIntentTools.isTool(action.action)&&!expected.packageName.equals(action.packageName))return "stale:动作应用与观察不一致";
        Graph now=null;
        try{
            actionPhase(work,"graph_read");
            now=readNativeActionGraph(taskId,expected,action,work,false);
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
                }else if(expected.capture!=null&&expected.capture.formHistory()||!graph.digest.equals(now.digest)){
                    if(work!=null&&work.nativeGuard!=null){
                        try{compareNativeAction(taskId,expected,action,now,work);work.nativeActionRevalidated=true;}
                        catch(ProfileOwnershipViolation identityChanged){throw identityChanged;}
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
            if(!refreshed||(!reference.signature.equals(nodeSignature(node,freshChildText))
                    &&!deferNativeSearchEntrySignature(taskId,expected,action,node,work))||!node.isVisibleToUser()||!node.isEnabled()){
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
                if(expected.capture!=null&&expected.capture.formHistory()
                        ||work!=null&&(work.nativeActionRevalidated||nativeSearchEntryGuard(work)||nativeFlightOpenGuard(work))){
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
        boolean nativeSearchInvalidRawVisibility; // Same-census raw visibility; never changes legacy row.visible.
        int nativeSearchRawVisibilityChecked; // Must cover every row before new typed admission.
        String nativeSearchFirstInvalidRawPath;java.util.List<Integer> nativeSearchFirstInvalidRawBounds;
        String packageName,digest,backgroundGeneration,backgroundBootstrapPackage;int windowId,rotation,displayId;Rect bounds;boolean truncated;
        List<String> backgroundAllowedPackages=java.util.Collections.emptyList();
        String backgroundSelectionRaw,backgroundOwnerSha;
        WindowOwnership profileWindow;
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
        long nativeActionCapturedAt,readStartedElapsedMs,readCompletedElapsedMs;
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
        boolean sameWindow(Graph other){requireSameProfileOwner(profileWindow,other.profileWindow);return windowId==other.windowId&&rotation==other.rotation&&displayId==other.displayId
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
            copy.backgroundSelectionRaw=backgroundSelectionRaw;copy.backgroundOwnerSha=backgroundOwnerSha;copy.profileWindow=profileWindow;
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
    /** Profile identity failures are terminal, never a same-App scene retry. */
    private static final class ProfileOwnershipViolation extends IllegalStateException {
        private static final long serialVersionUID=1L;
        ProfileOwnershipViolation(String reason){super(reason);}
        ProfileOwnershipViolation(String reason,Throwable cause){super(reason,cause);}
    }
    private static void requireSameProfileOwner(WindowOwnership original,WindowOwnership actual){
        if(!NativeAppEvidence.sameProfileOwner(original,actual))
            throw new ProfileOwnershipViolation("后台 profile、用户序列号或真实任务 token 已变化");
    }
    private static void requireSameProfileWindow(WindowOwnership original,WindowOwnership actual){
        requireSameProfileOwner(original,actual);
        if(original!=null&&original.windowId!=actual.windowId)
            throw new ProfileOwnershipViolation("后台 profile 证明不属于原观察窗口");
    }
    private static void requireHistoricalProfileWindow(BackgroundSession background,PhoneObservation frame){
        try{
            NativeAppEvidence.requireProfileTarget(background.profileTarget(),frame.profileWindow);
            // The Session retains the exact received proof object's provenance. Historical
            // capture validation cannot renew it; effects still require a new live RPC.
            if(frame.profileWindow!=null)background.requireHistoricalProfileWindow(frame.profileWindow,
                    frame.windowId,frame.profileWindow.taskId,frame.capturedElapsedMillis);
        }catch(RuntimeException unavailable){throw new ProfileOwnershipViolation("原观察缺少同 profile 的采集时归属证明",unavailable);}
    }
    /**
     * Public Parcelable output only; no hidden-API exemption, reflection, title
     * parsing, package-to-user inference or expected task ID participates.
     * The prefix is pinned to Android 16 qpr2 AOSP AccessibilityWindowInfo
     * 817452aae13e872cee097d147447676cd2e00077bcba7df476633c11b3b4e38c.
     * Runtime schema checks and independent broker leaf corroboration are both
     * required. Host checks do not qualify this platform adapter on a device.
     */
    static int actualProfileAccessibilityTaskId(AccessibilityWindowInfo window){
        if(android.os.Build.VERSION.SDK_INT!=36||window==null)
            throw new ProfileOwnershipViolation("当前平台没有已限定的 profile 窗口任务读取方式");
        Parcel parcel=Parcel.obtain(),roundTrip=Parcel.obtain();AccessibilityWindowInfo copy=null;
        try{
            window.writeToParcel(parcel,0);
            int bytes=parcel.dataSize();
            if(bytes<28||bytes>65536)throw new ProfileOwnershipViolation("profile 窗口 parcel 超出固定结构范围");
            parcel.setDataPosition(0);
            int display=parcel.readInt(),type=parcel.readInt(),layer=parcel.readInt(),flags=parcel.readInt();
            int id=parcel.readInt(),parent=parcel.readInt(),task=parcel.readInt();
            int publicFlags=(window.isActive()?1:0)|(window.isFocused()?2:0)
                    |(window.isAccessibilityFocused()?4:0)|(window.isInPictureInPictureMode()?8:0);
            if(display<=0||type!=AccessibilityWindowInfo.TYPE_APPLICATION||id<0||task<=0||parent< -1||parent==id
                    ||display!=window.getDisplayId()||type!=window.getType()||layer!=window.getLayer()
                    ||id!=window.getId()||flags!=publicFlags)
                throw new ProfileOwnershipViolation("profile 窗口 parcel 与公开窗口字段不一致");
            Region parsed=Region.CREATOR.createFromParcel(parcel),actual=new Region();
            window.getRegionInScreen(actual);Rect bounds=new Rect();window.getBoundsInScreen(bounds);
            if(parsed==null||bounds.isEmpty()||!parsed.equals(actual)||!parsed.getBounds().equals(bounds))
                throw new ProfileOwnershipViolation("profile 窗口 parcel 几何结构不一致");
            // The framework must consume and reproduce the complete actual parcel;
            // no partially decoded or trailing alternative schema is accepted.
            parcel.setDataPosition(0);copy=AccessibilityWindowInfo.CREATOR.createFromParcel(parcel);
            if(copy==null||parcel.dataPosition()!=bytes)
                throw new ProfileOwnershipViolation("profile 窗口 parcel 未被框架完整消费");
            copy.writeToParcel(roundTrip,0);
            if(!java.util.Arrays.equals(parcel.marshall(),roundTrip.marshall()))
                throw new ProfileOwnershipViolation("profile 窗口 parcel 完整往返不一致");
            return task;
        }catch(ProfileOwnershipViolation refused){throw refused;}
        catch(RuntimeException malformed){throw new ProfileOwnershipViolation("profile 窗口任务结构不可验证",malformed);}
        finally{if(copy!=null)copy.recycle();roundTrip.recycle();parcel.recycle();}
    }
    /** Local identity fence; a historical proof alone cannot authorize dispatch. */
    private static void requireActualProfileTask(BackgroundSession background,PhoneObservation frame,AccessibilityWindowInfo window){
        if(background.profileTarget()==null){
            if(frame.profileWindow!=null)throw new ProfileOwnershipViolation("普通 user0 任务收到 profile 观察");
            return;
        }
        requireHistoricalProfileWindow(background,frame);
        if(window==null||actualProfileAccessibilityTaskId(window)!=frame.profileWindow.taskId)
            throw new ProfileOwnershipViolation("实际可访问性窗口已不属于原 profile leaf");
    }
    /** Worker-only fresh RPC on the caller's existing cancellation and deadline. */
    private WindowOwnership readProfileWindow(AccessibilityNodeInfo root,BackgroundSession background,final GraphBudget budget){
        if(background==null||background.profileTarget()==null)return null;
        if(Looper.myLooper()==Looper.getMainLooper()||budget==null||budget.cancellation()==null
                ||budget.deadline()<=SystemClock.elapsedRealtime())
            throw new ProfileOwnershipViolation("profile 窗口复核必须在有界 worker 上执行");
        checkReadBudget(budget);List<AccessibilityWindowInfo> windows=null;AccessibilityWindowInfo nodeWindow=null;
        try{
            background.requireActive();
            if(root==null||root.getWindowId()<0||!background.profileTarget().packageName.equals(string(root.getPackageName())))
                throw new ProfileOwnershipViolation("profile 实际根窗口缺失");
            windows=windowsForDisplay(background.displayId());AccessibilityWindowInfo matched=null;int count=0;
            if(windows==null||windows.isEmpty()||windows.size()>64)
                throw new ProfileOwnershipViolation("profile 完整窗口集合不可用");
            for(AccessibilityWindowInfo candidate:windows){
                checkReadBudget(budget);
                if(candidate.getId()==root.getWindowId()){matched=candidate;count++;}
            }
            if(count!=1||matched==null||matched.getDisplayId()!=background.displayId()
                    ||matched.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION)
                throw new ProfileOwnershipViolation("profile 实际窗口不唯一或显示不符");
            int actualTask=actualProfileAccessibilityTaskId(matched);
            nodeWindow=root.getWindow();
            if(nodeWindow==null||nodeWindow.getId()!=matched.getId()||nodeWindow.getDisplayId()!=matched.getDisplayId()
                    ||actualProfileAccessibilityTaskId(nodeWindow)!=actualTask)
                throw new ProfileOwnershipViolation("profile 根与完整窗口集合任务身份不一致");
            final HeptaAccessibilityService.Cancellation cancellation=new HeptaAccessibilityService.Cancellation(){public boolean isCancelled(){
                try{budget.check();return budget.cancellation().isCancelled();}catch(RuntimeException retired){return true;}
            }};
            WindowOwnership proof=background.verifyProfileWindow(matched.getId(),actualTask,cancellation,budget.deadline());
            checkReadBudget(budget);
            background.requireProfileWindow(proof,matched.getId(),actualTask,SystemClock.elapsedRealtime());
            return proof;
        }catch(ProfileOwnershipViolation refused){throw refused;}
        catch(Exception unavailable){throw new ProfileOwnershipViolation("profile 实际任务归属复核失败",unavailable);}
        finally{
            if(nodeWindow!=null)nodeWindow.recycle();
            if(windows!=null)for(AccessibilityWindowInfo window:windows)window.recycle();
        }
    }
    private void finishProfileRead(Graph graph,BackgroundSession background,GraphBudget budget){
        AccessibilityNodeInfo root=selectedRoot(background,budget);
        if(root==null)throw new ProfileOwnershipViolation("profile 完整读取后窗口缺失");
        try{
            WindowOwnership after=readProfileWindow(root,background,budget);
            requireSameProfileOwner(graph.profileWindow,after);
            if(after.windowId!=graph.windowId)throw new StaleObservation("profile 同任务窗口在完整读取中换代");
            graph.profileWindow=after;
        }finally{root.recycle();}
    }
    private interface GraphBudget { void check(); default HeptaAccessibilityService.Cancellation cancellation(){return null;} default long deadline(){return 0;} }
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
        return snapshotNativeActionNode(node,path,parentClass,retained,reference,null);
    }
    private static NativeActionSnapshotCheck.Node snapshotNativeActionNode(AccessibilityNodeInfo node,String path,
            String parentClass,PhoneObservation.Node retained,NodeRef reference,Graph rawOwner){
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
        boolean rawVisible=node.isVisibleToUser();
        if(rawOwner!=null){rawOwner.nativeSearchRawVisibilityChecked++;if(rawVisible&&bounds.isEmpty()){
            rawOwner.nativeSearchInvalidRawVisibility=true;if(rawOwner.nativeSearchFirstInvalidRawPath==null){
                rawOwner.nativeSearchFirstInvalidRawPath=path;rawOwner.nativeSearchFirstInvalidRawBounds=java.util.Collections.unmodifiableList(
                        java.util.Arrays.asList(bounds.left,bounds.top,bounds.right,bounds.bottom));}}}
        row.put("visible",rawVisible&&!bounds.isEmpty());row.put("enabled",node.isEnabled());
        row.put("clickable",node.isClickable());row.put("editable",node.isEditable());row.put("scrollable",node.isScrollable());
        row.put("focused",node.isFocused());row.put("password",node.isPassword());
        row.put("selected",node.isSelected());row.put("checkable",node.isCheckable());row.put("checked",node.isChecked());
        row.put("children",node.getChildCount());row.put("scroll_actions",readScrollActions(node).fingerprintInput());
        row.put("ime_enter",readImeEnter(node).fingerprintInput());row.put("input_sha256",inputTextHash(node));
        row.put("action_click",hasAction(node,AccessibilityNodeInfo.ACTION_CLICK));
        return new NativeActionSnapshotCheck.Node(row);
    }
    /** Pure copy from the original complete read; partial/action graphs cannot enter this path. */
    private static FrozenObservationWindow frozenObservationWindow(Graph graph){
        if(graph==null||!graph.nativeObservationComplete||graph.nativeActionNodes==null||graph.nativeActionNodes.isEmpty()
                ||graph.nativeActionWindows==null||graph.state==null||graph.state.imeVisibility!=ImeVisibility.HIDDEN
                ||graph.windowMetadata==null||!"observed".equals(graph.windowMetadata.status)
                ||graph.windowMetadata.type==null||graph.windowMetadata.type.intValue()!=1
                ||graph.nativeActionWidth<=0||graph.nativeActionHeight<=0)return null;
        return new FrozenObservationWindow(graph.packageName,graph.windowId,graph.displayId,graph.rotation,
                graph.bounds.left,graph.bounds.top,graph.bounds.right,graph.bounds.bottom,
                graph.nativeActionWidth,graph.nativeActionHeight,graph.windowMetadata.bindFreshness(""),graph.nativeActionWindows,graph.profileWindow);
    }
    /** Post-encoding current identity only: never read root children, text, descriptions or node signatures. */
    private FrozenObservationWindow readFrozenObservationWindow(ObservationRequest request,CaptureIdentity identity){
        GraphBudget budget=observationBudget(request);checkReadBudget(budget);
        if(identity.frozenWindow==null||request.readAuthorization==null||request.readAuthorization!=taskAuthorization)
            throw new StaleObservation("封存观察的任务授权已变化");
        requireTaskAuthorization(request.taskId,taskAuthorization);
        AccessibilityNodeInfo root=selectedRoot(request.background,budget);
        if(root==null)throw new NoActiveWindow();
        try{
            checkReadBudget(budget);Graph window=new Graph();
            window.packageName=string(root.getPackageName());window.windowId=root.getWindowId();window.displayId=identity.displayId;
            window.bounds=new Rect();root.getBoundsInScreen(window.bounds);window.rotation=rotation(window.displayId);
            if(!root.isVisibleToUser()||window.bounds.isEmpty())throw new StaleObservation("封存观察的当前窗口不可见");
            window.windowMetadata=readWindowMetadata(root,window.bounds,window.windowId,window.displayId);
            window.profileWindow=readProfileWindow(root,request.background,budget);
            DisplayManager manager=(DisplayManager)getSystemService(DISPLAY_SERVICE);
            Display display=manager==null?null:manager.getDisplay(window.displayId);
            if(display==null||display.getRotation()!=window.rotation)throw new StaleObservation("封存观察的显示已变化");
            android.util.DisplayMetrics metrics=new android.util.DisplayMetrics();display.getRealMetrics(metrics);
            if(metrics.widthPixels<=0||metrics.heightPixels<=0)throw new StaleObservation("封存观察的显示尺寸未知");
            Map<String,Object> windows=readNativeActionWindows(window,budget);
            checkReadBudget(budget);requireTaskAuthorization(request.taskId,taskAuthorization);
            return new FrozenObservationWindow(window.packageName,window.windowId,window.displayId,window.rotation,
                    window.bounds.left,window.bounds.top,window.bounds.right,window.bounds.bottom,metrics.widthPixels,metrics.heightPixels,
                    window.windowMetadata.bindFreshness(""),windows,window.profileWindow);
        }finally{root.recycle();}
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
            NativeActionSnapshotCheck.Node row=snapshotNativeActionNode(node,path,parent,retained,reference,graph);
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
        final long readStartedAt=SystemClock.elapsedRealtime();checkReadBudget(budget);
        String actualSelectionRaw=null,actualOwnerSha=null;
        if(background!=null)try{
            background.requireActive();actualSelectionRaw=background.selection.json().toString();actualOwnerSha=background.ownerSha256;
        }catch(Exception missingSelection){throw new IllegalStateException("无法记录当前后台应用选择来源",missingSelection);}
        checkReadBudget(budget);
        AccessibilityNodeInfo root=selectedRoot(background,budget);if(root==null)throw new NoActiveWindow();
        Graph graph=new Graph();graph.readStartedElapsedMs=readStartedAt;
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
        graph.profileWindow=readProfileWindow(root,background,budget);
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
                    if(budget instanceof QueryGraphBudget)((QueryGraphBudget)budget).currentPath=nativePath;
                    if(background!=null&&node!=root&&!node.refresh())throw new StaleObservation("后台子节点已不可用，需重新观察",true);
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
            if(background!=null&&background.profileTarget()!=null)finishProfileRead(graph,background,budget);
            String binding=background==null?"":("background="+background.generation+"|display="+graph.displayId+"|owner="+graph.backgroundOwnerSha
                    +"|selection="+sha(graph.backgroundSelectionRaw.getBytes(StandardCharsets.UTF_8))+"|");
            if(graph.profileWindow!=null)binding+="profile="+NativeAppEvidence.fingerprint(
                    NativeAppEvidence.profileActionIdentity(graph.profileWindow))+"|";
            String appTree=sha((binding+graph.packageName+"|"+graph.windowId+"|"+graph.rotation+"|"+graph.bounds+"|"+signatures).getBytes(StandardCharsets.UTF_8));
            graph.state=new ObservationState(appTree,readImeVisibility(graph.windowId,graph.displayId));
            // Focus is newly model-visible evidence, not an expansion of the old progress predicate.
            graph.digest=sha(graph.windowMetadata.bindFreshness(graph.state.fingerprintInput()+"\nnode_focus="+focusStates+"\nnode_scroll_actions="+scrollStates)
                    .getBytes(StandardCharsets.UTF_8));checkReadBudget(budget);
            graph.nativeObservationComplete=nativeEvidence&&completeNativeObservationGraph(graph);
            if(nativeEvidence)finishNativeActionCensus(graph,budget);
            if(nativeEvidence)graph.diagnosticStamp=nativeDiagnosticStamp(graph);
            graph.freezeFlightSnapshots(budget);checkReadBudget(budget);graph.readCompletedElapsedMs=SystemClock.elapsedRealtime();return graph;
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
    /** Copy only the already completed immutable BFS. No window/node read or refresh. */
    private static ObservationDiagnostics.CensusStamp nativeDiagnosticCensus(Graph graph){
        try{
            if(graph==null||!graph.nativeObservationComplete||graph.truncated||graph.collectionStats==null||graph.collectionStats.truncated()
                    ||graph.collectionStats.pending!=0||graph.collectionStats.nodeBudgetOmissions!=0||graph.collectionStats.textBudgetOmissions!=0
                    ||graph.collectionStats.childSlotsOmitted!=0||graph.nativeActionNodes==null||graph.nativeActionNodes.isEmpty()
                    ||graph.collectionStats.visited!=graph.nativeActionNodes.size()||graph.nativeActionNodes.size()>ObservationDiagnostics.MAX_CENSUS_NODES
                    ||graph.nativeActionWindows==null||graph.state==null||graph.state.imeVisibility!=ImeVisibility.HIDDEN
                    ||graph.windowMetadata==null||graph.bounds==null||graph.nativeActionWidth<=0||graph.nativeActionHeight<=0
                    ||graph.nativeActionText<0||graph.nativeActionText>NativeActionSnapshotCheck.MAX_TEXT
                    ||graph.nativeActionBytes<0||graph.nativeActionBytes>NativeActionSnapshotCheck.MAX_BYTES)return null;
            Map<String,Object> identity=new LinkedHashMap<String,Object>();identity.put("task_id",graph.nativeActionTaskId);
            identity.put("owner_sha256",graph.backgroundOwnerSha);identity.put("package",graph.packageName);
            identity.put("background_generation",graph.backgroundGeneration);identity.put("display_id",graph.displayId);identity.put("window_id",graph.windowId);
            identity.put("rotation",graph.rotation);identity.put("width",graph.nativeActionWidth);identity.put("height",graph.nativeActionHeight);
            identity.put("root_bounds",java.util.Arrays.asList(graph.bounds.left,graph.bounds.top,graph.bounds.right,graph.bounds.bottom));
            identity.put("authorization_sha256",graph.nativeActionAuthorizationSha);identity.put("selection_sha256",graph.nativeActionSelectionSha);
            identity.put("target_sha256",graph.nativeActionTargetSha);identity.put("goal_sha256",graph.nativeActionGoalSha);
            if(graph.profileWindow!=null)identity.putAll(NativeAppEvidence.profileActionIdentity(graph.profileWindow));
            List<Map<String,Object>> rows=new ArrayList<Map<String,Object>>();
            for(NativeActionSnapshotCheck.Node node:graph.nativeActionNodes){if(node==null)return null;rows.add(node.v);}
            Map<String,Object> context=new LinkedHashMap<String,Object>();
            context.put("read_started_elapsed_ms",graph.readStartedElapsedMs);context.put("read_completed_elapsed_ms",graph.readCompletedElapsedMs);
            context.put("native_observation_complete",true);context.put("truncated",false);
            context.put("visited_nodes",graph.collectionStats.visited);context.put("retained_nodes",graph.collectionStats.retained);
            context.put("pending_nodes_at_stop",graph.collectionStats.pending);
            context.put("nodes_omitted_by_node_limit",graph.collectionStats.nodeBudgetOmissions);
            context.put("nodes_omitted_by_text_limit",graph.collectionStats.textBudgetOmissions);
            context.put("child_slots_omitted_by_traversal_limit",graph.collectionStats.childSlotsOmitted);
            context.put("native_text_utf16",graph.nativeActionText);context.put("native_node_value_bytes",graph.nativeActionBytes);
            context.put("reported_windows_complete",true);context.put("reported_windows",graph.nativeActionWindows);context.put("ime_visibility","hidden");
            return new ObservationDiagnostics.CensusStamp(identity,graph.state.appTreeSha256,graph.digest,
                    sha(graph.windowMetadata.bindFreshness("").getBytes(StandardCharsets.UTF_8)),graph.collectionStats.visited,rows,context);
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
        JSONObject proof=WebFlightNativeStability.compareNative(oldNative,newNative,permit.targetPath,permit.domEvidence());
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
        private final WebObservationTiming timing;private final WebObservationTiming.Phase readPhase,waitPhase;
        private final WebObservationTiming.Span queueTiming;
        FlightObservationRead(java.util.concurrent.Callable<T> read,Cancellation cancel,long deadline,Runnable cleanup){
            this(read,cancel,deadline,cleanup,null,null,null,null);
        }
        FlightObservationRead(java.util.concurrent.Callable<T> read,Cancellation cancel,long deadline,Runnable cleanup,
                WebObservationTiming timing,WebObservationTiming.Phase queuePhase,WebObservationTiming.Phase readPhase,
                WebObservationTiming.Phase waitPhase){
            this.read=read;this.cancel=cancel;this.deadline=deadline;this.cleanup=cleanup;
            this.timing=timing;this.readPhase=readPhase;this.waitPhase=waitPhase;
            queueTiming=WebObservationTiming.begin(timing,queuePhase,deadline);
        }
        void submissionRejected(Throwable failure){WebObservationTiming.failed(queueTiming,failure);}
        private void requireOpen(){
            if(cancel.isCancelled()||SystemClock.elapsedRealtime()>=deadline)
                throw new IllegalStateException("readonly Flight observation cancelled or expired");
        }
        @Override public void run(){
            T actual=null;Throwable failure=null;WebObservationTiming.Span readTiming=null;
            WebObservationTiming.complete(queueTiming);
            try{
                synchronized(this){if(abandoned)return;}
                readTiming=WebObservationTiming.begin(timing,readPhase,deadline);
                requireOpen();actual=read.call();requireOpen();
            }catch(Throwable refused){failure=refused;}
            finally{
                // Owned node copies and the process-wide read slot drain before any result is published.
                try{if(cleanup!=null)cleanup.run();}
                catch(Throwable releaseFailure){if(failure==null)failure=releaseFailure;else failure.addSuppressed(releaseFailure);}
                synchronized(this){
                    try{if(abandoned||failure!=null)releaseValue(actual);else value=actual;}
                    catch(Throwable releaseFailure){if(failure==null)failure=releaseFailure;else failure.addSuppressed(releaseFailure);}
                    if(failure==null)WebObservationTiming.complete(readTiming);else WebObservationTiming.failed(readTiming,failure);
                    error=failure;done=true;notifyAll();
                }
            }
        }
        private void releaseValue(Object result){
            if(result instanceof FlightObservationSnapshot)((FlightObservationSnapshot)result).close();
        }
        T await()throws Exception{
            boolean claimed=false;
            WebObservationTiming.Span waitTiming=WebObservationTiming.begin(timing,waitPhase,deadline);
            try{
                synchronized(this){
                    while(!done){requireOpen();wait(Math.min(50,Math.max(1,deadline-SystemClock.elapsedRealtime())));}
                    requireOpen();
                    if(error instanceof Exception)throw (Exception)error;
                    if(error instanceof Error)throw (Error)error;
                    T result=value;value=null;claimed=true;WebObservationTiming.complete(waitTiming);return result;
                }
            }catch(Exception|Error failure){WebObservationTiming.failed(waitTiming,failure);throw failure;}
            finally{if(!claimed)synchronized(this){abandoned=true;releaseValue(value);value=null;}}
        }
    }
    private <T>T readFlightObservationOnMain(java.util.concurrent.Callable<T> read,Cancellation cancel,long deadline,
            WebObservationTiming timing)throws Exception{
        if(Looper.myLooper()==Looper.getMainLooper())throw new IllegalStateException("Flight observation waits only on its worker");
        FlightObservationRead<T> call=new FlightObservationRead<T>(read,cancel,deadline,null,timing,
                WebObservationTiming.Phase.MAIN_QUEUE,WebObservationTiming.Phase.MAIN_READ,WebObservationTiming.Phase.MAIN_WAIT);
        if(!main.post(call)){
            IllegalStateException failure=new IllegalStateException("readonly Flight observation main looper unavailable");
            call.submissionRejected(failure);throw failure;
        }
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
        if(locked(source.background))throw new StaleObservation("Flight只读观察的显示范围锁状态或凭据不可用");
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
        },cancel,deadline,web.observationTiming());
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
        final WebObservationTiming timing=web.observationTiming();
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
            }public Cancellation cancellation(){return cancel;}public long deadline(){return deadline;}};
            FlightObservationRead<JSONObject> call=new FlightObservationRead<JSONObject>(new java.util.concurrent.Callable<JSONObject>(){
                public JSONObject call()throws Exception{
                    return verifyFlightObservationOnWorker(web,ownedSource,ownedObserved,after,first,last,cancel,deadline,budget,timing);
                }
            },cancel,deadline,cleanup,timing,WebObservationTiming.Phase.NATIVE_QUEUE,
                    WebObservationTiming.Phase.NATIVE_READ,WebObservationTiming.Phase.NATIVE_WAIT);
            // Unexpected submission failure keeps capacity fenced; only definitive rejection proves no read entered.
            ownershipTransferred=true;
            try{observationIo.execute(call);}
            catch(java.util.concurrent.RejectedExecutionException rejected){call.submissionRejected(rejected);cleanup.run();throw rejected;}
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
            Cancellation cancel,long deadline,GraphBudget budget,WebObservationTiming timing)throws Exception{
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
        WebObservationTiming.Span domTiming=WebObservationTiming.begin(timing,WebObservationTiming.Phase.NATIVE_DOM_BRACKET,deadline);
        JSONObject proof;
        try{
        proof=web.purpose.shopping!=null
                ?WebShoppingObservationStability.compareReadonlyObservationBracket(web.taskId,new JSONObject(source.frameRaw),
                        beforeNative,new JSONObject(observedSource.frameRaw),observedNative,firstCapture,lastCapture,source.targetPath)
                :WebFlightNativeStability.compareObservationBracket(web.taskId,new JSONObject(source.frameRaw),
                        beforeNative,new JSONObject(observedSource.frameRaw),observedNative,firstCapture,lastCapture,source.targetPath);
        WebObservationTiming.complete(domTiming);
        }catch(Exception|Error failure){
            WebObservationTiming.failed(domTiming,failure);
            if(web.purpose.shopping!=null){
                WebObservationTiming.failureStructure(domTiming,failure,beforeNative,observedNative,source.targetPath);
                try{
                    final String beforeRaw=source.graph.flightNativeSnapshotRaw,afterRaw=observed.flightNativeSnapshotRaw;
                    final String targetPath=source.targetPath;
                    WebObservationTiming.failureGeometry(domTiming,failure,new WebObservationTiming.FailureDiagnostic(){
                        public String[] collect(){return WebShoppingObservationStability.containmentFailureDiagnostic(
                                failure,beforeNative,observedNative,beforeRaw,afterRaw,targetPath);}
                    });
                }catch(Throwable unavailable){/* Optional diagnostics cannot replace the original rejection. */}
            }
            throw failure;
        }
        WebObservationTiming.Span finalTiming=null;
        try{
            WebObservationTiming.Span graphTiming=WebObservationTiming.begin(timing,WebObservationTiming.Phase.NATIVE_READ_GRAPH,deadline);
            try{
                checkReadBudget(budget);liveGraph=readGraph(budget,source.background);checkReadBudget(budget);
                WebObservationTiming.complete(graphTiming);
            }catch(Exception|Error failure){WebObservationTiming.failed(graphTiming,failure);throw failure;}
            finalTiming=WebObservationTiming.begin(timing,WebObservationTiming.Phase.NATIVE_FINAL_RECHECK,deadline);
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
                liveProof=WebFlightNativeStability.compareNative(observedNative,liveNative,source.targetPath,proof.getJSONObject("dom"));
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
            JSONObject result=proof.put("source","private_service_snapshot_and_live_complete_native_traversal")
                    .put("original_target_obtained_before_graph_recycling",true)
                    .put("original_node_ref_identity_preserved",true).put("actual_ancestor_chain_refreshed",true)
                    .put("source_retained_elapsed_ms",source.retainedAt)
                    .put("first_ax_captured_elapsed_ms",source.frame.capturedElapsedMillis)
                    .put("last_ax_captured_elapsed_ms",after.capturedElapsedMillis)
                    .put("started_elapsed_ms",started).put("checked_elapsed_ms",SystemClock.elapsedRealtime())
                    .put("live_native_recheck",liveProof).put("interactive_windows_before",windowsBefore)
                    .put("interactive_windows_after",windowsAfter).put("two_interactive_window_reads_equal",true)
                    .put("native_invocation_entered",false);
            WebObservationTiming.complete(finalTiming);return result;
        }catch(Exception|Error failure){WebObservationTiming.failed(finalTiming,failure);throw failure;}
        finally{if(liveGraph!=null)liveGraph.close();}
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
