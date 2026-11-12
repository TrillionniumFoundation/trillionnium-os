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
    /**
     * Service-created, read-only source for one observation bracket. It owns an
     * independent copy of the original target, never the old Graph or its refs.
     */
    static final class FlightObservationSnapshot implements AutoCloseable {
        private final HeptaAccessibilityService service;private final WebFlightSession web;
        private final BackgroundSession background;private final QualificationScopeConfig.Bound scope;
        private final TaskAuthorization.Gate authorization;private final PhoneObservation frame;
        private final NodeRef original;private final String targetPath,frameRaw,nativeRaw,ownerSha,selectionRaw;
        private final long retainedAt;private volatile boolean closed;
        private FlightObservationSnapshot(HeptaAccessibilityService service,WebFlightSession web,
                BackgroundSession background,QualificationScopeConfig.Bound scope,TaskAuthorization.Gate authorization,
                PhoneObservation frame,NodeRef original,String targetPath,String frameRaw,String nativeRaw,
                String ownerSha,String selectionRaw,long at){
            this.service=service;this.web=web;this.background=background;this.scope=scope;this.authorization=authorization;
            this.frame=frame;this.original=original;this.targetPath=targetPath;this.frameRaw=frameRaw;this.nativeRaw=nativeRaw;
            this.ownerSha=ownerSha;this.selectionRaw=selectionRaw;retainedAt=at;
        }
        @Override public void close(){
            synchronized(this){if(closed)return;closed=true;}
            Runnable release=new Runnable(){public void run(){original.node.recycle();}};
            if(Looper.myLooper()==Looper.getMainLooper())release.run();
            else if(!service.main.post(release)){
                // A stopped main looper cannot use this closed copy again.
                release.run();throw new IllegalStateException("native observation copy release could not be posted");
            }
        }
    }
    public interface ObservationCallback { void onObservation(PhoneObservation value); void onError(String error); }
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
            this.accepted=accepted;this.dispatched=dispatched;this.stale=stale;this.detail=detail;
            this.appCatalogue=appCatalogue;this.qualificationScope=scope;this.taskAuthorization=authorization;this.backgroundSession=background;this.imeSubmit=imeSubmit;this.fixedIntent=fixedIntent;
            this.toolChild=toolChild;
        }
        ActionOutcome withScope(JSONObject scope){return new ActionOutcome(accepted,dispatched,stale,detail,appCatalogue,scope,taskAuthorization,backgroundSession,imeSubmit,fixedIntent,toolChild);
        }
        ActionOutcome withAuthorization(JSONObject authorization){return new ActionOutcome(accepted,dispatched,stale,detail,appCatalogue,qualificationScope,authorization,backgroundSession,imeSubmit,fixedIntent,toolChild);}
        ActionOutcome withBackground(JSONObject background){return new ActionOutcome(accepted,dispatched,stale,detail,appCatalogue,qualificationScope,taskAuthorization,background,imeSubmit,fixedIntent,toolChild);}
        ActionOutcome withSubmit(JSONObject value){return new ActionOutcome(accepted,dispatched,stale,detail,appCatalogue,qualificationScope,taskAuthorization,backgroundSession,value,fixedIntent,toolChild);}
        ActionOutcome withFixedIntent(JSONObject value){return new ActionOutcome(accepted,dispatched,stale,detail,appCatalogue,qualificationScope,taskAuthorization,backgroundSession,imeSubmit,value,toolChild);}
        ActionOutcome withToolChild(JSONObject value){return new ActionOutcome(accepted,dispatched,stale,detail,appCatalogue,qualificationScope,taskAuthorization,backgroundSession,imeSubmit,fixedIntent,value);}
    }
    private static volatile HeptaAccessibilityService live;
    public static HeptaAccessibilityService connected() { return live; }
    // UI observers only. Task admission always reads the current service again.
    private static final java.util.Set<Runnable> connectionListeners=new java.util.concurrent.CopyOnWriteArraySet<Runnable>();
    static void addConnectionListener(Runnable listener){if(listener==null)throw new NullPointerException("listener");connectionListeners.add(listener);}
    static void removeConnectionListener(Runnable listener){connectionListeners.remove(listener);}
    private void publishConnectionChange(){for(Runnable listener:connectionListeners)main.post(listener);}
    private final Handler main=new Handler(Looper.getMainLooper());
    private String lease;
    private QualificationScopeConfig.Bound taskScope;
    private TaskAuthorization.Gate taskAuthorization;
    private NotesTaskPhaseGuard taskNotesPhase;
    private CalculatorTaskInputGuard taskCalculatorInput;
    private BackgroundSession taskBackground;
    private WebFlightSession taskWeb;
    private SubmitAttemptGuard taskSubmitAttempts;
    private FixedIntentAttemptGuard taskFixedIntentAttempts;
    private final java.util.concurrent.ExecutorService backgroundIo=java.util.concurrent.Executors.newSingleThreadExecutor();
    private Runnable stopListener;
    private LocalTaskController ownedController;
    private long lastScreenshotAt;
    private boolean capturePending;
    private long captureSerial;
    private ObservationRequest activeObservation;
    private PhoneObservation current;
    private Graph currentGraph;
    private Bitmap currentBitmap;
    private static final long MAX_OBSERVATION_AGE_MS=90000;
    // Bounded across the whole selected tree, including structural/nonvisible
    // nodes. A real browser snapshot had 975 nodes before its deeper controls.
    // Output remains independently bounded and native exact-token admission is unchanged.
    private static final int MAX_NODES=128, MAX_VISITED=1536, MAX_CHARACTERS=6144;
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
    @Override public void onAccessibilityEvent(AccessibilityEvent event) { /* Read again at every decision and effect. */ }
    @Override public void onInterrupt() { requestStop(); }
    @Override public void onDestroy() {
        LocalTaskController controller; synchronized(this){controller=ownedController;}
        if(controller!=null)controller.close();
        if(taskWeb!=null)taskWeb.serviceRetired();
        requestStop();
        if(activeObservation!=null)failObservation(activeObservation,"无障碍服务已断开");
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
                &&activeObservation==null&&!capturePending
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
        if(lease!=null || live!=this||WebFlightSession.hasUnreleased(this))return false;taskWeb=null;lease=taskId;stopListener=onStop;appDiscovery=null;taskScope=null;taskAuthorization=null;taskNotesPhase=null;taskCalculatorInput=null;taskBackground=null;taskSubmitAttempts=null;taskFixedIntentAttempts=null;return true;
    }
    public synchronized void releaseTask(String taskId) { if(taskId.equals(lease)){
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

    /** Each observation owns its samples/capture and the caller's original deadline. */
    private static final class ObservationRequest {
        final String taskId;final File directory;final ObservationCallback callback;final Cancellation cancel;
        final ObservationStabilityGate gate;
        Graph captured;long token;int intervalRetries;boolean finished,shotPending;
        ObservationRequest(String taskId,File directory,ObservationCallback callback,Cancellation cancel,long deadline){
            this.taskId=taskId;this.directory=directory;this.callback=callback;this.cancel=cancel;
            this.gate=new ObservationStabilityGate(SystemClock.elapsedRealtime(),deadline);
        }
    }
    public void observe(final String taskId,final File evidenceDirectory,final Cancellation cancel,
                        final long deadline,final ObservationCallback callback) {
        final ObservationRequest request=new ObservationRequest(taskId,evidenceDirectory,callback,cancel,deadline);
        main.post(new Runnable(){public void run(){
            if(activeObservation!=null){
                ObservationRequest old=activeObservation;
                if(!owns(old.taskId)||old.cancel.isCancelled())failObservation(old,"任务已经停止");
                else {callback.onError("已有屏幕观察尚未结束");return;}
            }
            if(capturePending){callback.onError("已有截图尚未结束");return;}
            activeObservation=request;sampleObservation(request);
        }});
    }
    private boolean observationActive(ObservationRequest request){
        if(request.finished||activeObservation!=request)return false;
        if(!request.gate.requestAlive(SystemClock.elapsedRealtime(),owns(request.taskId)&&!request.cancel.isCancelled())){
            failObservation(request,"任务停止或本次观察已超时");return false;
        }
        if(locked()){failObservation(request,"手机已锁定，请正常解锁后重新发起任务");return false;}
        return true;
    }
    private static ObservationStabilityGate.FrameKey frameKey(Graph graph){
        return new ObservationStabilityGate.FrameKey(graph.packageName,graph.windowId,graph.rotation,
                graph.bounds.left,graph.bounds.top,graph.bounds.right,graph.bounds.bottom,graph.digest,graph.truncated);
    }
    private static boolean sameObservedFrame(Graph a,Graph b){
        return a.sameWindowAndTree(b)&&a.truncated==b.truncated;
    }
    private void sampleObservation(final ObservationRequest request){
        if(!observationActive(request))return;
        Graph graph=null;
        try{
            try{graph=readGraph();}catch(NoActiveWindow|StaleObservation busy){/* A missing root or failed node refresh supplies no stable frame. */}
            long now=SystemClock.elapsedRealtime();
            ObservationStabilityGate.Result result=request.gate.sample(now,graph==null?null:frameKey(graph),true);
            if(result==ObservationStabilityGate.Result.EXPIRED||result==ObservationStabilityGate.Result.CANCELLED){
                failObservation(request,"窗口仍在变化或没有活动窗口，未取得稳定观察");return;
            }
            long screenshotDelay=Math.max(0,400-(now-lastScreenshotAt));
            if(result==ObservationStabilityGate.Result.READY&&screenshotDelay==0){
                request.captured=graph;graph=null;captureObservation(request);return;
            }
            long delay=request.gate.nextSampleDelay(now);
            if(result==ObservationStabilityGate.Result.READY)delay=Math.min(delay,screenshotDelay);
            main.postDelayed(new Runnable(){public void run(){sampleObservation(request);}},delay);
        }catch(Exception error){failObservation(request,"无法读取当前活动窗口："+message(error));}
        finally{if(graph!=null)graph.close();}
    }
    private void failObservation(ObservationRequest request,String error){
        if(request.finished)return;
        request.finished=true;request.gate.retire();
        if(request.shotPending&&captureSerial==request.token){capturePending=false;captureSerial++;}
        request.shotPending=false;
        if(request.captured!=null){request.captured.close();request.captured=null;}
        if(activeObservation==request)activeObservation=null;
        request.callback.onError(error);
    }
    private void retryObservation(final ObservationRequest request,long delay){
        if(request.captured!=null){request.captured.close();request.captured=null;}
        request.gate.resetEvidence();
        if(!observationActive(request))return;
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
        capturePending=true;request.shotPending=true;lastScreenshotAt=SystemClock.elapsedRealtime();
        final long token=++captureSerial;request.token=token;
        watchCapture(request,lastScreenshotAt+5000);
        try{takeScreenshot(request.captured.displayId,getMainExecutor(),new TakeScreenshotCallback(){
            @Override public void onFailure(int code){
                if(request.finished||activeObservation!=request||captureSerial!=token)return;
                capturePending=false;captureSerial++;request.shotPending=false;
                if(!observationActive(request))return;
                if(code==ERROR_TAKE_SCREENSHOT_INTERVAL_TIME_SHORT&&request.intervalRetries++<1)
                    retryObservation(request,500);
                else failObservation(request,"系统截图失败，错误码 "+code+"；不会绕过受保护画面");
            }
            @Override public void onSuccess(ScreenshotResult result){
                if(request.finished||activeObservation!=request||captureSerial!=token){result.getHardwareBuffer().close();return;}
                capturePending=false;captureSerial++;request.shotPending=false;
                Bitmap bitmap=null;Graph after=null;
                try{
                    bitmap=copyScreenshot(result);
                    if(!observationActive(request))return;
                    try{after=readGraph();}catch(NoActiveWindow|StaleObservation busy){retryObservation(request,200);return;}
                    if(!sameObservedFrame(request.captured,after)){retryObservation(request,200);return;}
                    after.close();after=null;
                    if(bitmap.getWidth()<1||bitmap.getHeight()<1||(long)bitmap.getWidth()*bitmap.getHeight()>16000000L)
                        throw new IllegalStateException("屏幕尺寸超出观察范围");
                    if(!request.directory.isDirectory())throw new IllegalStateException("任务证据目录不存在");
                    String id=UUID.randomUUID().toString().replace("-","");File path=new File(request.directory,id+".png");
                    if(!path.createNewFile())throw new IllegalStateException("观察标识重复");
                    try(FileOutputStream stream=new FileOutputStream(path)){
                        if(!bitmap.compress(Bitmap.CompressFormat.PNG,100,stream))throw new IllegalStateException("截图编码失败");
                        stream.getFD().sync();
                    }
                    path.setReadable(false,false);path.setReadable(true,true);path.setWritable(false,false);path.setWritable(true,true);
                    String digest=fileSha256(path);
                    // Encoding/fsync/hash can take time. Recheck the full observed graph before publication.
                    if(!observationActive(request))return;
                    try{after=readGraph();}catch(NoActiveWindow|StaleObservation busy){retryObservation(request,200);return;}
                    if(!sameObservedFrame(request.captured,after)){retryObservation(request,200);return;}
                    after.close();after=null;
                    if(!observationActive(request))return;
                    Graph graph=request.captured;
                    PhoneObservation observation=new PhoneObservation(id,graph.packageName,SystemClock.elapsedRealtime(),
                            bitmap.getWidth(),bitmap.getHeight(),graph.rotation,graph.windowId,graph.bounds,path,digest,graph.digest,graph.state,graph.windowMetadata,graph.truncated,graph.rows,graph.backgroundGeneration,graph.backgroundBootstrapPackage,graph.backgroundAllowedPackages,graph.collectionStats,
                            graph.backgroundSelectionRaw==null?null:new JSONObject(graph.backgroundSelectionRaw),graph.backgroundOwnerSha);
                    clearSnapshot();current=observation;currentGraph=graph;currentBitmap=bitmap;
                    request.captured=null;bitmap=null; // Ownership transfers only here. Late callbacks cannot close this snapshot.
                    request.finished=true;request.gate.retire();activeObservation=null;
                    request.callback.onObservation(observation);
                }catch(Exception error){failObservation(request,"观察失败："+message(error));}
                finally{if(after!=null)after.close();if(bitmap!=null)bitmap.recycle();}
            }
        });}catch(Exception error){failObservation(request,"系统截图不可用："+message(error));}
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
    /** Runs on the service thread immediately before each actual tool dispatch. */
    private void scopeBeforeDispatch(String taskId,QualificationScopeConfig.Bound dispatchScope,PhoneObservation expected,ActionDecision action,AccessibilityNodeInfo node,boolean nodeRequired){
        QualificationScopeConfig.Bound scope=scopeFor(taskId);
        QualificationScope.require(scope==dispatchScope,"dispatch scope was retired");
        AccessibilityNodeInfo root=null;AccessibilityWindowInfo window=null;
        try{
            scope.verifyUnchanged();
            backgroundBeforeDispatch(taskId,expected,action,node,nodeRequired);
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
            boolean refreshed=!nodeRequired||(node!=null&&node.refresh());
            String operation="click".equals(action.action)&&action.nodeId==null?"coordinate_click":action.action;
            scope.gate.check(operation,action.packageName,frame,!refreshed||node==null?null:string(node.getPackageName()),!refreshed||node==null?null:Integer.valueOf(node.getWindowId()),nodeRequired);
            if(nodeRequired){
                NodeRef ref=currentGraph==null?null:currentGraph.refs.get(action.nodeId);
                QualificationScope.require(ref!=null&&ref.node==node&&node.isVisibleToUser()&&node.isEnabled()
                        &&ref.signature.equals(nodeSignature(node,observedChildText(node))),"scope node changed before dispatch");
            }
            QualificationScope.require(frame!=null&&expected!=null&&frame.packageName.equals(expected.packageName)&&frame.windowId==expected.windowId,
                    "fresh scope window differs from bound observation");
            QualificationScope.require(ownsScope(taskId,scope),"scope lease retired before dispatch");
        }catch(StaleObservation changed){throw changed;}
        catch(Exception error){scope.refuse(message(error));throw new QualificationScope.Violation(message(error));}
        finally{if(window!=null)window.recycle();if(root!=null)root.recycle();}
    }
    private void backgroundBeforeDispatch(String taskId,PhoneObservation expected,ActionDecision action,AccessibilityNodeInfo node,boolean nodeRequired){
        BackgroundSession background=backgroundFor(taskId);if(background==null)return;
        requireBackgroundObservation(taskId,expected);
        if("home".equals(action.action))throw new IllegalArgumentException("后台任务不提供 HOME，也不会回退到主屏导航");
        if("click".equals(action.action)&&action.nodeId==null)throw new IllegalArgumentException("后台任务只接受已观察节点动作，不派发坐标手势");
        if(!background.allows(action.packageName))throw new IllegalArgumentException("动作应用超出本次后台范围");
        AccessibilityNodeInfo root=null;AccessibilityWindowInfo window=null;
        try{
            root=selectedRoot();window=root==null?null:root.getWindow();
            if(root==null||window==null||window.getDisplayId()!=background.displayId()
                    ||window.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION||root.getWindowId()!=expected.windowId
                    ||!expected.packageName.equals(string(root.getPackageName()))||!root.isVisibleToUser())
                throw new IllegalStateException("后台目标窗口已变化");
            if(nodeRequired){
                NodeRef ref=currentGraph==null?null:currentGraph.refs.get(action.nodeId);
                if(node==null||ref==null||ref.node!=node)throw new IllegalStateException("后台节点不属于本次观察");
                boolean refreshed=node.refresh();background.requireActive();
                if(!refreshed)throw new StaleObservation("后台节点已不可用，需重新观察");
                // Identity failures stay terminal, even when the same refresh also changes text.
                requireBackgroundNodeWindow(background,expected,node);
                if(!node.isVisibleToUser()||!node.isEnabled()
                        ||!ref.signature.equals(nodeSignature(node,observedChildText(node,true))))
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
        // Capture this task's source once. A late callback must never look up a
        // retired lease or borrow a newly started task's scope.
        final QualificationScopeConfig.Bound captured;final TaskAuthorization.Gate capturedAuthorization;final BackgroundSession capturedBackground;
        synchronized(this){captured=owns(taskId)?taskScope:null;capturedAuthorization=owns(taskId)?taskAuthorization:null;capturedBackground=owns(taskId)?taskBackground:null;}
        final ActionCallback boundCallback=new ActionCallback(){public void onResult(ActionOutcome result){
            boolean currentLease=ownsScope(taskId,captured)&&ownsAuthorization(taskId,capturedAuthorization)&&capturedAuthorization==expectedAuthorization&&ownsBackground(taskId,capturedBackground),stopped=cancel.isCancelled();
            ActionOutcome delivered=currentLease&&!stopped?result:new ActionOutcome(false,result.dispatched,false,
                    "任务已停止或租约已退休；保留已发生的派发，不接受迟到回执",result.appCatalogue).withSubmit(result.imeSubmit).withFixedIntent(result.fixedIntent);
            callback.onResult(delivered.withScope(callbackScopeEvidence(taskId,captured,currentLease,stopped))
                    .withAuthorization(callbackAuthorizationEvidence(capturedAuthorization,currentLease,stopped))
                    .withBackground(capturedBackground==null?null:capturedBackground.evidence())
                    .withToolChild(decision.toolChildOrigin==null?null:new JSONObject(decision.toolChildOrigin.evidence())));
        }};
        main.post(new Runnable(){public void run(){
            if(!ownsScope(taskId,captured)||!ownsAuthorization(taskId,capturedAuthorization)||capturedAuthorization!=expectedAuthorization||!ownsBackground(taskId,capturedBackground)||cancel.isCancelled()){
                boundCallback.onResult(new ActionOutcome(false,false,false,"任务已停止或作用范围未绑定"));return;
            }
            if(decision.toolChildOrigin!=null)try{
                decision.toolChildOrigin.enterService(taskId,capturedAuthorization.authorization.sha256,modelRunId,expected.id);
            }catch(Exception refused){boundCallback.onResult(new ActionOutcome(false,false,false,message(refused)));return;}
            performOnMain(taskId,expected,decision,targets,fixedTarget,cancel,boundCallback,captured,capturedAuthorization,modelRunId);
        }});
    }
    private static String targetBindingError(PhoneObservation expected,ActionDecision action,ObservedTargetLabels targets){
        // The label/id pair is the immutable prompt projection, never a live-tree substitution.
        if(expected==null||targets==null||!expected.id.equals(targets.observationId)||!expected.packageName.equals(targets.packageName))
            return "目标标签投影不属于本次观察";
        if(action.nodeId!=null&&!targets.matches(action.observationId,action.packageName,action.nodeId,action.nodeLabel))
            return "节点文字与标识不是本次观察提供的原始配对";
        return null;
    }
    private String validate(String taskId,PhoneObservation expected,ActionDecision action,ObservedTargetLabels targets,Cancellation cancel){
        if(cancel.isCancelled()||!owns(taskId))return "任务已停止";
        if(locked())return "手机已锁定";
        try{requireBackgroundObservation(taskId,expected);}catch(Exception mismatch){return "后台观察无效："+message(mismatch);}
        if(expected!=current||currentGraph==null||!expected.id.equals(action.observationId))return "stale:观察标识已失效";
        String bindingError=targetBindingError(expected,action,targets);if(bindingError!=null)return bindingError;
        long age=SystemClock.elapsedRealtime()-expected.capturedElapsedMillis;
        if(age<0||age>MAX_OBSERVATION_AGE_MS)return "stale:观察已过期";
        if(!"open".equals(action.action)&&!org.trillionnium.hepta.background.FixedIntentTools.isTool(action.action)&&!expected.packageName.equals(action.packageName))return "stale:动作应用与观察不一致";
        Graph now=null;
        try{
            now=readGraph();
            if(!currentGraph.sameWindow(now))return "stale:目标窗口已变化";
            if(ActionPolicy.requiresStableTree(action)){
                WebFlightSession web=taskWeb;
                WebFlightNativeStability.Permit permit=web==null?null:web.flightNativePermitForDispatch(action,expected);
                if(permit!=null){
                    try{web.acceptFlightNativeCheck(action,expected,
                            requireLiveFlightNativeStability(taskId,expected,action,permit,now,cancel));}
                    catch(Exception mismatch){throw new StaleObservation("stale:首页目标局部复核失败："+message(mismatch));}
                }else if(!currentGraph.digest.equals(now.digest))return "stale:目标窗口内容已变化";
            }
        }
        catch(StaleObservation changed){return message(changed);}
        catch(Exception e){return backgroundFor(taskId)==null?"stale:无法复核当前窗口":"后台窗口复核失败："+message(e);}
        finally{if(now!=null)now.close();}
        return null;
    }
    private void performOnMain(final String taskId,final PhoneObservation expected,final ActionDecision action,
                               final ObservedTargetLabels targets,final org.trillionnium.hepta.background.FixedIntentTarget fixedTarget,final Cancellation cancel,final ActionCallback callback,
                               final QualificationScopeConfig.Bound dispatchScope,final TaskAuthorization.Gate authorization,final String modelRunId){
        try{
            authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
            if(backgroundFor(taskId)!=null){
                String bindingError=targetBindingError(expected,action,targets);
                if(bindingError!=null)throw new IllegalArgumentException(bindingError);
            }
            scopeBeforeDispatch(taskId,dispatchScope,expected,action,null,false);
            if((scopeFor(taskId).config!=null||backgroundFor(taskId)!=null)&&("click".equals(action.action)||"type".equals(action.action)||"submit".equals(action.action)||"scroll".equals(action.action))){
                NodeRef ref=currentGraph==null?null:currentGraph.refs.get(action.nodeId);
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,ref==null?null:ref.node,true);
            }
        }
        catch(Exception error){callback.onResult(new ActionOutcome(false,false,error instanceof StaleObservation,message(error)));return;}
        String invalid=validate(taskId,expected,action,targets,cancel);
        if(invalid!=null){callback.onResult(new ActionOutcome(false,false,invalid.startsWith("stale:"),invalid));return;}
        try{
            if("wait".equals(action.action)){
                main.postDelayed(new Runnable(){public void run(){callback.onResult(new ActionOutcome(!cancel.isCancelled(),false,false,cancel.isCancelled()?"等待已停止":"等待结束"));}},action.durationMs);return;
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
                dispatchFixedIntent(taskId,expected,action,targets,fixedTarget,authorization,modelRunId,cancel,callback,dispatchScope);return;
            }
            if("open".equals(action.action)){
                if(backgroundFor(taskId)!=null){dispatchBackgroundNavigation(taskId,expected,action,authorization,modelRunId,cancel,callback);return;}
                refreshApps();if(!launchable.containsKey(action.packageName))throw new IllegalArgumentException("目标不是已列出的可启动应用");
                Intent launch=getPackageManager().getLaunchIntentForPackage(action.packageName);
                if(launch==null)throw new IllegalArgumentException("找不到应用启动入口");
                launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TOP);
                if(cancel.isCancelled()){callback.onResult(new ActionOutcome(false,false,false,"任务已停止"));return;}
                scopeOpenIntent(taskId,dispatchScope,action.packageName,launch);
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,null,false);
                authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                startActivity(launch);
                try{authorization.opened(action,modelRunId);}catch(Exception retiredAfterOpen){
                    callback.onResult(new ActionOutcome(false,true,false,"应用打开已派发，但授权回执未完成："+message(retiredAfterOpen)));return;
                }
                finishAfter(700,true,"已请求打开应用，下一步将重新观察",callback);return;
            }
            if("back".equals(action.action)||"home".equals(action.action)){
                if(backgroundFor(taskId)!=null){dispatchBackgroundNavigation(taskId,expected,action,authorization,modelRunId,cancel,callback);return;}
                if(cancel.isCancelled()){callback.onResult(new ActionOutcome(false,false,false,"任务已停止"));return;}
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,null,false);
                authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                boolean accepted=performGlobalAction("back".equals(action.action)?GLOBAL_ACTION_BACK:GLOBAL_ACTION_HOME);
                finishAfter(350,accepted,accepted?"系统导航已接受":"系统导航未接受",callback);return;
            }
            if("click".equals(action.action)&&action.nodeId==null){coordinateClick(taskId,expected,action,targets,authorization,modelRunId,cancel,callback);return;}
            NodeRef reference=currentGraph.refs.get(action.nodeId);
            if(reference==null)throw new IllegalArgumentException("节点不属于这次观察");
            AccessibilityNodeInfo node=reference.node;
            boolean refreshed=node.refresh();
            if(scopeFor(taskId).config!=null){
                if(!refreshed){scopeFor(taskId).refuse("scope node refresh failed");throw new QualificationScope.Violation("scope node refresh failed");}
            }
            BackgroundSession background=backgroundFor(taskId);
            if(refreshed&&background!=null)requireBackgroundNodeWindow(background,expected,node);
            ObservedChildText.Result freshChildText=refreshed?observedChildText(node,background!=null):ObservedChildText.notApplicable();
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
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,node,true);
                authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                WebFlightSession web=taskWeb;
                if(web!=null){
                    WebRegionNativeBridge region=web.nativeRegionForDispatch(action,modelRunId,expected);
                    if(region!=null){
                        web.acceptNativeRegionCheck(action,modelRunId,
                                requireLiveNativeRegion(taskId,expected,node,region,cancel));
                        scopeBeforeDispatch(taskId,dispatchScope,expected,action,node,true);
                        authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                    }
                    web.beforeNativeClickInvocation(action,modelRunId);
                }
                accepted=node.performAction(AccessibilityNodeInfo.ACTION_CLICK);
                finishAfter(350,accepted,accepted?"节点点击已接受":"节点点击未接受",callback);
            }else if("type".equals(action.action)){
                if(!node.isEditable()||!hasAction(node,AccessibilityNodeInfo.ACTION_SET_TEXT))throw new IllegalArgumentException("目标不是可写文本节点");
                Bundle args=new Bundle();args.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,action.text);
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,node,true);
                authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                accepted=node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT,args);
                if(!accepted){callback.onResult(new ActionOutcome(false,false,false,"文本写入未被接受"));return;}
                main.postDelayed(new Runnable(){public void run(){
                    if(cancel.isCancelled()||!ownsScope(taskId,dispatchScope)||!ownsAuthorization(taskId,authorization)){
                        callback.onResult(new ActionOutcome(false,true,false,"文本已派发，任务已停止；不读取退休节点"));return;
                    }
                    try{
                        boolean verified=reference.node.refresh()&&action.text.equals(string(reference.node.getText()));
                        callback.onResult(new ActionOutcome(verified,true,false,verified?"文本已按原文回读验证":"文本操作已发送，但原文回读未通过；不重试"));
                    }catch(RuntimeException retiredNode){
                        callback.onResult(new ActionOutcome(false,true,false,"文本已派发，但节点回读不可用；不重试"));
                    }
                }},300);
            }else if("submit".equals(action.action)){
                if(!(ActionDecision.IME_ACTION_SCHEMA.equals(action.actionSchema)||ActionDecision.FIXED_INTENT_ACTION_SCHEMA.equals(action.actionSchema))||!reference.imeEnter.queryAllowed()
                        ||!node.isEditable()||!node.isFocused()||!ObservedImeEnter.isSha(reference.inputTextSha256))
                    throw new IllegalArgumentException("当前字段没有已观察且语义明确的查询提交动作");
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,node,true);
                authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                final SubmitAttemptGuard guard=submitFor(taskId);
                requireSubmitWindow(node,expected.windowId,currentGraph.displayId);
                final SubmitAttemptGuard.Attempt attempt=guard.consume(new SubmitAttemptGuard.Binding(taskId,modelRunId,
                        expected.id,expected.packageName,action.nodeId,expected.windowId,currentGraph.displayId,
                        expected.backgroundGeneration,reference.inputTextSha256,reference.imeEnter));
                try{
                    // The durable journal can take time. Revalidate before consuming the platform call.
                    String changed=validate(taskId,expected,action,targets,cancel);
                    if(changed!=null)throw new IllegalStateException(changed);
                    scopeBeforeDispatch(taskId,dispatchScope,expected,action,node,true);
                    authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                    if(cancel.isCancelled()||!node.refresh()||!node.isEditable()||!node.isFocused()||!node.isVisibleToUser()
                            ||!node.isEnabled()||node.isPassword()||node.getWindowId()!=expected.windowId
                            ||!expected.packageName.equals(string(node.getPackageName()))
                            ||!reference.signature.equals(nodeSignature(node,observedChildText(node,background!=null))))
                        throw new IllegalStateException("提交记录已消费，但字段或任务已变化；未调用编辑器，不重试");
                    requireSubmitWindow(node,expected.windowId,currentGraph.displayId);
                    guard.entering(attempt);
                    boolean apiAccepted=node.performAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.getId());
                    final JSONObject proof=new JSONObject(guard.finished(attempt,Boolean.valueOf(apiAccepted)));
                    final ActionOutcome result=new ActionOutcome(apiAccepted,true,false,apiAccepted
                            ?"查询编辑器动作已接受；业务结果仍需重新观察，不重试相同输入":"查询编辑器动作未接受；已记录尝试，不重试").withSubmit(proof);
                    main.postDelayed(new Runnable(){public void run(){callback.onResult(result);}},350);
                }catch(Exception uncertain){
                    Map<String,Object> proof=guard.evidence(attempt);
                    boolean entered=Boolean.TRUE.equals(proof.get("dispatch_attempted"));
                    callback.onResult(new ActionOutcome(false,entered,false,"查询提交未完成："+message(uncertain)+"；保留消费记录，不重试")
                            .withSubmit(new JSONObject(proof)));
                }
            }else if("scroll".equals(action.action)){
                int operation=scrollAction(action.direction);
                if(!hasAction(node,operation))throw new IllegalArgumentException("这个节点未提供所选滚动方向");
                scopeBeforeDispatch(taskId,dispatchScope,expected,action,node,true);
                authorizationBeforeDispatch(taskId,authorization,action,modelRunId);
                accepted=node.performAction(operation);finishAfter(450,accepted,accepted?"滚动已接受":"滚动未接受",callback);
            }else throw new IllegalArgumentException("不支持的动作");
        }catch(Exception e){callback.onResult(new ActionOutcome(false,false,e instanceof StaleObservation,message(e)));}
    }
    /** IPC runs off the service/main thread. A missing reply is a possible dispatch, never a retry. */
    private void dispatchFixedIntent(final String taskId,final PhoneObservation expected,final ActionDecision action,
            final ObservedTargetLabels labels,final org.trillionnium.hepta.background.FixedIntentTarget target,
            final TaskAuthorization.Gate authorization,final String run,final Cancellation cancel,final ActionCallback callback,
            final QualificationScopeConfig.Bound scope)throws Exception{
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
        final FixedIntentAttemptGuard.Attempt attempt=ledger.consume(new FixedIntentAttemptGuard.Binding(taskId,run,expected.id,
                expected.packageName,expected.windowId,display,background==null?null:background.generation,target,payload));
        try{
            if(cancel.isCancelled())throw new IllegalStateException("task cancelled before fixed intent");
            String invalid=validate(taskId,expected,action,labels,cancel);if(invalid!=null)throw new IllegalStateException(invalid);
            scopeBeforeDispatch(taskId,scope,expected,action,null,false);authorizationBeforeDispatch(taskId,authorization,action,run);
            org.trillionnium.hepta.background.FixedIntentDispatch.recheck(this,caller,target);
            if(background==null){
                Intent intent=org.trillionnium.hepta.background.FixedIntentDispatch.intent(target,payload);
                ledger.entering(attempt);
                try{startActivity(intent);ledger.finished(attempt,Boolean.TRUE);}
                catch(Exception unknown){ledger.finished(attempt,null);callback.onResult(new ActionOutcome(false,true,false,"固定本地入口派发结果未知，不自动重试："+message(unknown)).withFixedIntent(new JSONObject(ledger.evidence(attempt))));return;}
                main.postDelayed(new Runnable(){public void run(){callback.onResult(new ActionOutcome(true,true,false,
                        "固定本地入口请求已接受；须重新观察编辑器/搜索页，尚未证明保存或查询结果").withFixedIntent(new JSONObject(ledger.evidence(attempt))));}},700);
                return;
            }
            backgroundIo.execute(new Runnable(){public void run(){
                boolean entered=false;
                try{
                    if(cancel.isCancelled()||!ownsBackground(taskId,background))throw new IllegalStateException("background task retired");
                    scope.verifyUnchanged();authorizationBeforeDispatch(taskId,authorization,action,run);background.requireActive();
                    org.trillionnium.hepta.background.FixedIntentDispatch.recheck(HeptaAccessibilityService.this,caller,target);
                    ledger.entering(attempt);entered=true;
                    JSONObject response=background.fixedIntent(target,payload,attempt.id,cancel);
                    ledger.finished(attempt,Boolean.TRUE);
                    final JSONObject proof=new JSONObject(ledger.evidence(attempt)).put("broker_response",response);
                    main.postDelayed(new Runnable(){public void run(){callback.onResult(new ActionOutcome(true,true,false,
                            "后台固定本地入口已派发；须重新观察，尚未证明保存或查询结果").withFixedIntent(proof));}},350);
                }catch(final Exception failure){
                    if(entered)ledger.finished(attempt,null);
                    final JSONObject proof=new JSONObject(ledger.evidence(attempt));final boolean dispatched=entered;
                    main.post(new Runnable(){public void run(){callback.onResult(new ActionOutcome(false,dispatched,false,
                            "后台固定本地入口未得到完整确认，不自动重试："+message(failure)).withFixedIntent(proof));}});
                }
            }});
        }catch(Exception beforeCall){callback.onResult(new ActionOutcome(false,false,false,"固定本地入口未派发，尝试已消费："+message(beforeCall)).withFixedIntent(new JSONObject(ledger.evidence(attempt))));}
    }

    private void dispatchBackgroundNavigation(final String id,final PhoneObservation expected,final ActionDecision action,
            final TaskAuthorization.Gate authorization,final String modelRunId,final Cancellation cancel,final ActionCallback callback){
        final BackgroundSession background=backgroundFor(id);
        if(background==null||"home".equals(action.action)){callback.onResult(new ActionOutcome(false,false,false,"后台 HOME 不可用"));return;}
        try{backgroundIo.execute(new Runnable(){public void run(){
            boolean sent=false;
            try{
                if(cancel.isCancelled()||!ownsBackground(id,background))throw new IllegalStateException("后台任务已停止");
                scopeFor(id).verifyUnchanged();authorizationBeforeDispatch(id,authorization,action,modelRunId);
                background.requireActive();sent=true;
                JSONObject receipt=background.action("open".equals(action.action)?"launch":"back",action.packageName,cancel);
                final boolean dispatched=receipt.optBoolean("dispatched",true);
                if("open".equals(action.action)&&dispatched)authorization.opened(action,modelRunId);
                final ActionOutcome result=new ActionOutcome(true,dispatched,false,"后台工具已定向派发；下一步重新观察");
                main.postDelayed(new Runnable(){public void run(){callback.onResult(result);}},350);
            }catch(Exception error){
                final ActionOutcome result=new ActionOutcome(false,sent,false,"后台工具未完成："+message(error)+(sent?"；可能已有派发，不重试":""));
                main.post(new Runnable(){public void run(){callback.onResult(result);}});
            }
        }});}catch(RuntimeException unavailable){callback.onResult(new ActionOutcome(false,false,false,"后台执行队列已关闭"));}
    }
    private void finishAfter(long delay,final boolean accepted,final String detail,final ActionCallback callback){
        main.postDelayed(new Runnable(){public void run(){callback.onResult(new ActionOutcome(accepted,accepted,false,detail));}},delay);
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
                    fresh=copyScreenshot(result);String invalid=validate(taskId,expected,action,targets,cancel);
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
            // Preserve the original observed signatures. Never recalculate them
            // from a later refresh while pretending they were the source frame.
            signature=original.signature;appTreeSignature=original.appTreeSignature;
            imeEnter=original.imeEnter;inputTextSha256=original.inputTextSha256;
            node=AccessibilityNodeInfo.obtain(original.node);
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
        String packageName,digest,backgroundGeneration,backgroundBootstrapPackage;int windowId,rotation,displayId;Rect bounds;boolean truncated;
        List<String> backgroundAllowedPackages=java.util.Collections.emptyList();
        String backgroundSelectionRaw,backgroundOwnerSha;
        ObservationState state;
        ObservedWindowMetadata windowMetadata;
        final List<PhoneObservation.Node> rows=new ArrayList<PhoneObservation.Node>();
        final Map<String,NodeRef> refs=new HashMap<String,NodeRef>();
        JSONArray flightNativeSnapshot;boolean flightNativeSnapshotComplete;int flightNativeSnapshotText;
        boolean sameWindow(Graph other){return windowId==other.windowId&&rotation==other.rotation&&displayId==other.displayId
                &&java.util.Objects.equals(backgroundGeneration,other.backgroundGeneration)
                &&java.util.Objects.equals(backgroundSelectionRaw,other.backgroundSelectionRaw)
                &&java.util.Objects.equals(backgroundOwnerSha,other.backgroundOwnerSha)
                &&packageName.equals(other.packageName)&&bounds.equals(other.bounds);}
        boolean sameWindowAndTree(Graph other){return sameWindow(other)&&digest.equals(other.digest);}
        void close(){for(NodeRef n:refs.values())n.node.recycle();refs.clear();}
    }
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
    private AccessibilityNodeInfo selectedRoot(){
        BackgroundSession background=currentBackground();
        if(background==null)return getRootInActiveWindow();
        background.requireActive();List<AccessibilityWindowInfo> windows=windowsForDisplay(background.displayId());
        AccessibilityWindowInfo chosen=null;
        try{
            for(AccessibilityWindowInfo window:windows){
                if(window==null||window.getDisplayId()!=background.displayId()||window.getType()!=AccessibilityWindowInfo.TYPE_APPLICATION)continue;
                if(chosen==null||(window.isFocused()&&!chosen.isFocused())
                        ||(window.isFocused()==chosen.isFocused()&&window.getLayer()>chosen.getLayer()))chosen=window;
            }
            if(chosen==null)throw new NoActiveWindow();
            AccessibilityNodeInfo root=chosen.getRoot();if(root==null)throw new NoActiveWindow();
            try{
                boolean refreshed=root.refresh();background.requireActive();
                if(!refreshed)throw new StaleObservation("后台根节点已不可用，需重新观察");
                if(root.getWindowId()!=chosen.getId()||!background.allows(string(root.getPackageName()))||!root.isVisibleToUser())
                    throw new IllegalStateException("后台屏幕出现未授权应用或不可见窗口，任务停止");
                return root;
            }catch(RuntimeException error){root.recycle();throw error;}
        }finally{for(AccessibilityWindowInfo window:windows)if(window!=null)window.recycle();}
    }
    private Graph readGraph(){
        BackgroundSession background=currentBackground();
        String actualSelectionRaw=null,actualOwnerSha=null;
        if(background!=null)try{
            background.requireActive();actualSelectionRaw=background.selection.json().toString();actualOwnerSha=background.ownerSha256;
        }catch(Exception missingSelection){throw new IllegalStateException("无法记录当前后台应用选择来源",missingSelection);}
        AccessibilityNodeInfo root=selectedRoot();if(root==null)throw new NoActiveWindow();
        WebFlightSession activeWeb=taskWeb;
        boolean webEvidence=activeWeb!=null&&background!=null&&activeWeb.taskId.equals(background.taskId)
                &&background.selection.allowedPackages.equals(java.util.Collections.singletonList(
                        org.trillionnium.hepta.webprotocol.WebEvidenceProtocol.HELPER_PACKAGE));
        int retainedLimit=webEvidence?WEB_MAX_NODES:MAX_NODES,textLimit=webEvidence?WEB_MAX_CHARACTERS:MAX_CHARACTERS;
        Graph graph=new Graph();graph.displayId=background==null?Display.DEFAULT_DISPLAY:background.displayId();
        if(webEvidence&&activeWeb.goal!=null){graph.flightNativeSnapshot=new JSONArray();graph.flightNativeSnapshotComplete=true;}
        graph.backgroundGeneration=background==null?null:background.generation;
        graph.backgroundBootstrapPackage=background==null?null:background.selection.initialPackage;
        graph.backgroundAllowedPackages=background==null?java.util.Collections.<String>emptyList():background.selection.allowedPackages;
        graph.backgroundSelectionRaw=actualSelectionRaw;graph.backgroundOwnerSha=actualOwnerSha;
        graph.packageName=string(root.getPackageName());graph.windowId=root.getWindowId();graph.rotation=rotation(graph.displayId);graph.bounds=new Rect();root.getBoundsInScreen(graph.bounds);
        if(graph.packageName.isEmpty()||graph.bounds.isEmpty()){root.recycle();throw new IllegalStateException("活动窗口身份不可用");}
        graph.windowMetadata=readWindowMetadata(root,graph.bounds,graph.windowId,graph.displayId);
        if(background!=null&&(graph.windowMetadata.displayId==null||graph.windowMetadata.displayId.intValue()!=graph.displayId
                ||!background.allows(graph.packageName))){root.recycle();throw new IllegalStateException("后台观察窗口越界");}
        ArrayDeque<AccessibilityNodeInfo> queue=new ArrayDeque<AccessibilityNodeInfo>();queue.add(root);
        ArrayDeque<String> nativePaths=new ArrayDeque<String>(),nativeParents=new ArrayDeque<String>();
        nativePaths.add("0");nativeParents.add("");
        StringBuilder signatures=new StringBuilder(),focusStates=new StringBuilder(),scrollStates=new StringBuilder();int visited=0,characters=0;
        int nodeBudgetOmissions=0,textBudgetOmissions=0;long childSlotsOmitted=0,started=SystemClock.elapsedRealtime();
        try{
            while(!queue.isEmpty()&&visited<MAX_VISITED){
                AccessibilityNodeInfo node=queue.removeFirst();visited++;
                String nativePath=nativePaths.removeFirst(),nativeParentClass=nativeParents.removeFirst();
                try{
                    // selectedRoot refreshed the root before graph metadata was read.
                    // Descendants may still be cached; never publish an old body as a new frame.
                    if(background!=null&&node!=root&&!node.refresh())throw new StaleObservation("后台子节点已不可用，需重新观察");
                    Rect bounds=new Rect();node.getBoundsInScreen(bounds);boolean visible=node.isVisibleToUser()&&!bounds.isEmpty();
                    String text=node.isPassword()?"":limited(string(node.getText()),96);
                    String description=node.isPassword()?"":limited(string(node.getContentDescription()),96);
                    ObservedScrollActions scrollActions=readScrollActions(node);
                    ObservedImeEnter imeEnter=readImeEnter(node);String inputHash=inputTextHash(node);
                    boolean useful=visible&&(node.isClickable()||node.isEditable()||node.isScrollable()||!text.isEmpty()||!description.isEmpty());
                    if(useful){
                        ObservedChildText.Result childText=graph.rows.size()<retainedLimit?observedChildText(node,background!=null):ObservedChildText.notApplicable();
                        if(graph.rows.size()<retainedLimit&&characters+text.length()+description.length()+childText.text.length()<textLimit){
                            String id="n"+graph.rows.size();NodeRef reference=new NodeRef(node,childText,scrollActions,imeEnter,inputHash);graph.refs.put(id,reference);signatures.append(reference.appTreeSignature).append('|')
                                    .append(nativePath).append('|').append(nativeParentClass).append('\n');
                            scrollStates.append(id).append('=').append(scrollActions.fingerprintInput()).append('\n');
                            boolean focused=node.isFocused();focusStates.append(id).append('=').append(focused).append('|').append(imeEnter.fingerprintInput()).append('|').append(inputHash).append('\n');
                            graph.rows.add(new PhoneObservation.Node(id,string(node.getPackageName()),string(node.getClassName()),limited(string(node.getViewIdResourceName()),96),text,description,bounds,node.isClickable(),node.isEditable(),node.isScrollable(),node.isEnabled(),focused,node.isPassword(),childText,scrollActions,imeEnter,inputHash,
                                    node.isEditable()&&focused&&node.isEnabled()&&!node.isPassword()&&imeEnter.queryAllowed()&&submitAvailable(string(node.getPackageName()),inputHash),reference.appTreeSignature,
                                    nativePath.isEmpty()?null:nativePath,nativePath.isEmpty()?null:nativeParentClass));
                            characters+=text.length()+description.length()+childText.text.length();
                        }else{
                            graph.truncated=true;
                            if(graph.rows.size()>=retainedLimit)nodeBudgetOmissions++;else textBudgetOmissions++;
                        }
                    }
                    int actualChildren=node.getChildCount();
                    if(graph.flightNativeSnapshot!=null&&graph.flightNativeSnapshotComplete){
                        try{
                            if(graph.flightNativeSnapshot.length()>=WebFlightNativeStability.MAX_NATIVE_NODES)
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
                        AccessibilityNodeInfo child=node.getChild(index);
                        if(child!=null){
                            queue.add(child);
                            // Beyond this small position budget retain the node, but publish no hierarchy claim.
                            nativePaths.add(nativePath.isEmpty()||nativePath.length()>=240?"":nativePath+"/"+index);
                            nativeParents.add(limited(string(node.getClassName()),96));
                        }else if(background!=null)throw new StaleObservation("后台子树已变化，需重新观察");
                    }
                }finally{node.recycle();}
            }
            if(!queue.isEmpty())graph.truncated=true;
            graph.collectionStats=new PhoneObservation.CollectionStats(MAX_VISITED,retainedLimit,textLimit,
                    visited,graph.rows.size(),characters,queue.size(),nodeBudgetOmissions,textBudgetOmissions,
                    childSlotsOmitted,SystemClock.elapsedRealtime()-started);
            String binding=background==null?"":("background="+background.generation+"|display="+graph.displayId+"|owner="+graph.backgroundOwnerSha
                    +"|selection="+sha(graph.backgroundSelectionRaw.getBytes(StandardCharsets.UTF_8))+"|");
            String appTree=sha((binding+graph.packageName+"|"+graph.windowId+"|"+graph.rotation+"|"+graph.bounds+"|"+signatures).getBytes(StandardCharsets.UTF_8));
            graph.state=new ObservationState(appTree,readImeVisibility(graph.windowId,graph.displayId));
            // Focus is newly model-visible evidence, not an expansion of the old progress predicate.
            graph.digest=sha(graph.windowMetadata.bindFreshness(graph.state.fingerprintInput()+"\nnode_focus="+focusStates+"\nnode_scroll_actions="+scrollStates)
                    .getBytes(StandardCharsets.UTF_8));return graph;
        }catch(RuntimeException e){graph.close();throw e;}
        finally{while(!queue.isEmpty())queue.removeFirst().recycle();}
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
            WebFlightNativeStability.Permit permit,Graph now,Cancellation cancel)throws Exception{
        long started=SystemClock.elapsedRealtime();BackgroundSession background=backgroundFor(taskId);Graph before=currentGraph;
        if(background==null||before==null||frame!=current||cancel.isCancelled()||!owns(taskId)
                ||!taskId.equals(permit.taskId)||permit.frame!=frame||permit.windowId!=before.windowId
                ||permit.displayId!=before.displayId||!before.sameWindow(now)
                ||before.truncated||now.truncated||before.collectionStats==null||now.collectionStats==null
                ||before.collectionStats.truncated()||now.collectionStats.truncated()
                ||!before.flightNativeSnapshotComplete||!now.flightNativeSnapshotComplete
                ||before.flightNativeSnapshot==null||now.flightNativeSnapshot==null
                ||before.flightNativeSnapshot.length()!=before.collectionStats.visited
                ||now.flightNativeSnapshot.length()!=now.collectionStats.visited
                ||before.state.imeVisibility!=ImeVisibility.HIDDEN||now.state.imeVisibility!=ImeVisibility.HIDDEN
                ||!before.windowMetadata.bindFreshness("").equals(now.windowMetadata.bindFreshness("")))
            throw new StaleObservation("完整原生树、输入法或窗口元数据不可证明");
        background.requireActive();
        NodeRef original=before.refs.get(action.nodeId),fresh=null;
        for(PhoneObservation.Node row:now.rows)if(permit.targetPath.equals(row.nativeTreePath)){
            if(fresh!=null)throw new StaleObservation("原生目标路径不唯一");fresh=now.refs.get(row.id);
        }
        if(original==null||fresh==null||!original.node.equals(fresh.node)||!original.signature.equals(fresh.signature))
            throw new StaleObservation("原始节点引用与同路径新目标不相同");
        JSONObject proof=WebFlightNativeStability.compareNative(before.flightNativeSnapshot,now.flightNativeSnapshot,permit.targetPath);
        JSONArray oldRetained=new JSONArray(),newRetained=new JSONArray();
        for(PhoneObservation.Node row:before.rows)oldRetained.put(row.json());
        for(PhoneObservation.Node row:now.rows)newRetained.put(row.json());
        proof.put("retained_node_pairing",WebFlightNativeStability.compareRetained(oldRetained,newRetained,
                proof.getString("native_slider_path")));
        JSONObject windowsBefore=readRegionWindows(frame,permit.displayId,permit.windowId,permit.bounds());
        refreshFlightTargetChain(background,frame,original,permit.targetPath,before.flightNativeSnapshot);
        if(!original.signature.equals(nodeSignature(original.node,observedChildText(original.node,true))))
            throw new StaleObservation("原始目标最后签名已变化");
        JSONObject windowsAfter=readRegionWindows(frame,permit.displayId,permit.windowId,permit.bounds());
        if(!org.trillionnium.hepta.webprotocol.WebDomCanonical.same(windowsBefore,windowsAfter))
            throw new StaleObservation("首页点击前窗口覆盖关系已变化");
        background.requireActive();
        if(cancel.isCancelled()||!owns(taskId)||frame!=current)throw new StaleObservation("首页任务已退休");
        return new FlightNativeCheck(frame,permit,started,SystemClock.elapsedRealtime(),proof,windowsAfter,before.digest.equals(now.digest));
    }
    private void refreshFlightTargetChain(BackgroundSession background,PhoneObservation frame,NodeRef original,
                                         String targetPath,JSONArray snapshot)throws Exception{
        java.util.Map<String,JSONObject> records=new java.util.HashMap<String,JSONObject>();
        for(int i=0;i<snapshot.length();i++){JSONObject row=snapshot.getJSONObject(i);records.put(row.getString("path"),row);}
        java.util.List<AccessibilityNodeInfo> owned=new java.util.ArrayList<AccessibilityNodeInfo>();
        AccessibilityNodeInfo cursor=original.node;String path=targetPath;
        Rect target=new Rect();cursor.getBoundsInScreen(target);
        try{
            for(int depth=0;depth<64;depth++){
                JSONObject expected=records.get(path);
                if(expected==null||!cursor.refresh()||!cursor.isVisibleToUser()||!cursor.isEnabled()||cursor.isPassword())
                    throw new StaleObservation("首页目标祖先不可用");
                requireBackgroundNodeWindow(background,frame,cursor);
                Rect actual=new Rect();cursor.getBoundsInScreen(actual);
                if(!actual.contains(target)||!org.trillionnium.hepta.webprotocol.WebDomCanonical.same(expected,
                        snapshotFlightNode(cursor,path,expected.getString("parent_class"))))
                    throw new StaleObservation("首页目标祖先或原生几何已变化");
                AccessibilityNodeInfo parent=cursor.getParent();if(parent!=null)owned.add(parent);
                if("0".equals(path)){
                    if(parent!=null)throw new StaleObservation("首页原生根边界变化");return;
                }
                int slash=path.lastIndexOf('/'),index=Integer.parseInt(path.substring(slash+1));
                if(parent==null||!parent.refresh()||index>=parent.getChildCount()
                        ||!expected.getString("parent_class").equals(string(parent.getClassName())))
                    throw new StaleObservation("首页目标父节点关系变化");
                AccessibilityNodeInfo child=parent.getChild(index);if(child!=null)owned.add(child);
                if(child==null||!child.refresh()||!child.equals(cursor))throw new StaleObservation("首页目标父子身份变化");
                cursor=parent;path=path.substring(0,slash);
            }
            throw new StaleObservation("首页原生祖先预算不足");
        }finally{for(AccessibilityNodeInfo node:owned)node.recycle();}
    }
    /** Worker waits without holding the service monitor; every graph read runs on main. */
    private final class FlightObservationRead<T> implements Runnable {
        private final java.util.concurrent.Callable<T> read;private final Cancellation cancel;private final long deadline;
        private boolean done,abandoned;private T value;private Throwable error;
        FlightObservationRead(java.util.concurrent.Callable<T> read,Cancellation cancel,long deadline){
            this.read=read;this.cancel=cancel;this.deadline=deadline;
        }
        private void requireOpen(){
            if(cancel.isCancelled()||SystemClock.elapsedRealtime()>=deadline)
                throw new IllegalStateException("readonly Flight observation cancelled or expired");
        }
        @Override public void run(){
            synchronized(this){if(abandoned){done=true;notifyAll();return;}}
            T actual=null;Throwable failure=null;
            try{requireOpen();actual=read.call();requireOpen();}catch(Throwable refused){failure=refused;}
            finally{
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
            }finally{
                if(!claimed)synchronized(this){abandoned=true;releaseValue(value);value=null;}
            }
        }
    }
    private <T>T readFlightObservationOnMain(java.util.concurrent.Callable<T> read,Cancellation cancel,long deadline)throws Exception{
        if(Looper.myLooper()==Looper.getMainLooper())throw new IllegalStateException("Flight observation waits only on its worker");
        FlightObservationRead<T> call=new FlightObservationRead<T>(read,cancel,deadline);
        if(!main.post(call))throw new IllegalStateException("readonly Flight observation main looper unavailable");
        return call.await();
    }
    private Graph requireFlightObservationCurrent(WebFlightSession web,PhoneObservation frame,Cancellation cancel)throws Exception{
        if(Looper.myLooper()!=Looper.getMainLooper()||web==null||web.goal==null||taskWeb!=web
                ||frame==null||frame!=current||currentGraph==null||cancel.isCancelled()||!owns(web.taskId)||locked())
            throw new StaleObservation("Flight只读观察已退休或不是当前主线程图");
        QualificationScopeConfig.Bound scope=scopeFor(web.taskId);scope.verifyUnchanged();scope.requireReady();
        TaskAuthorization.Gate authorization=authorizationFor(web.taskId);
        if(authorization!=web.authorization)throw new StaleObservation("Flight只读观察授权已被替换");
        authorization.ready();requireBackgroundObservation(web.taskId,frame);
        if(backgroundFor(web.taskId)==null)throw new StaleObservation("Flight只读观察没有实际后台租约");
        return currentGraph;
    }
    private static boolean completeFlightGraph(Graph graph){
        return graph!=null&&!graph.truncated&&graph.collectionStats!=null&&!graph.collectionStats.truncated()
                &&graph.collectionStats.pending==0&&graph.collectionStats.childSlotsOmitted==0
                &&graph.flightNativeSnapshotComplete&&graph.flightNativeSnapshot!=null
                &&graph.flightNativeSnapshot.length()==graph.collectionStats.visited
                &&graph.state.imeVisibility==ImeVisibility.HIDDEN;
    }
    FlightObservationSnapshot retainFlightObservation(final WebFlightSession web,final PhoneObservation frame,
            final Cancellation cancel,final long deadline)throws Exception{
        return readFlightObservationOnMain(new java.util.concurrent.Callable<FlightObservationSnapshot>(){
            public FlightObservationSnapshot call()throws Exception{
                Graph graph=requireFlightObservationCurrent(web,frame,cancel);
                if(!completeFlightGraph(graph))return null;
                PhoneObservation.Node target=null;
                for(PhoneObservation.Node row:graph.rows)if("android.widget.Button".equals(row.className)
                        &&WebFlightNativeStability.LABEL.equals(row.label())&&row.nativeTreePath!=null){
                    if(target!=null)return null;target=row;
                }
                if(target==null)return null;
                NodeRef ref=graph.refs.get(target.id);if(ref==null)return null;
                String frameRaw=org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(frame.toJson());
                String nativeRaw=org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(graph.flightNativeSnapshot);
                BackgroundSession background=backgroundFor(web.taskId);background.requireActive();
                return new FlightObservationSnapshot(HeptaAccessibilityService.this,web,background,scopeFor(web.taskId),
                        authorizationFor(web.taskId),frame,new NodeRef(ref),target.nativeTreePath,frameRaw,nativeRaw,
                        graph.backgroundOwnerSha,graph.backgroundSelectionRaw,SystemClock.elapsedRealtime());
            }
        },cancel,deadline);
    }
    JSONObject verifyFlightObservationBracket(final WebFlightSession web,final FlightObservationSnapshot source,
            final PhoneObservation after,final WebEvidenceReceipt first,final WebEvidenceReceipt last,
            final Cancellation cancel,final long deadline)throws Exception{
        return readFlightObservationOnMain(new java.util.concurrent.Callable<JSONObject>(){
            public JSONObject call()throws Exception{
                long started=SystemClock.elapsedRealtime();Graph observed=requireFlightObservationCurrent(web,after,cancel),liveGraph=null;
                if(source==null||source.service!=HeptaAccessibilityService.this||source.web!=web||source.closed
                        ||source.background!=backgroundFor(web.taskId)||source.scope!=scopeFor(web.taskId)
                        ||source.authorization!=authorizationFor(web.taskId)||!completeFlightGraph(observed)
                        ||!java.util.Objects.equals(source.ownerSha,observed.backgroundOwnerSha)
                        ||!java.util.Objects.equals(source.selectionRaw,observed.backgroundSelectionRaw))
                    throw new StaleObservation("Flight只读观察来源不属于当前任务或完整原生图");
                if(!"captured".equals(first.status)||!"captured".equals(last.status)
                        ||!first.bindingSha.equals(last.bindingSha)||source.frame.capturedElapsedMillis>source.retainedAt
                        ||source.retainedAt>first.started||first.ended>after.capturedElapsedMillis
                        ||after.capturedElapsedMillis>last.started||last.ended>started)
                    throw new StaleObservation("Flight只读观察与真实capture时序不同");
                JSONObject firstCapture=first.capture(),lastCapture=last.capture(),binding=firstCapture.getJSONObject("binding");
                if(!web.taskId.equals(binding.getString("task_id"))||!source.ownerSha.equals(binding.getString("owner_sha256"))
                        ||!source.authorization.authorization.sha256.equals(
                                binding.getJSONObject("authorization").getString("authorization_sha256")))
                    throw new StaleObservation("Flight只读capture的任务或OWNER来源不同");
                JSONArray beforeNative=new JSONArray(source.nativeRaw);
                JSONObject proof=WebFlightNativeStability.compareObservationBracket(web.taskId,new JSONObject(source.frameRaw),
                        beforeNative,after.toJson(),observed.flightNativeSnapshot,firstCapture,lastCapture,source.targetPath);
                try{
                    liveGraph=readGraph();
                    if(!completeFlightGraph(liveGraph)||!observed.sameWindow(liveGraph)
                            ||!observed.windowMetadata.bindFreshness("").equals(liveGraph.windowMetadata.bindFreshness("")))
                        throw new StaleObservation("Flight只读观察最后完整图或窗口已变化");
                    JSONObject liveProof=WebFlightNativeStability.compareNative(observed.flightNativeSnapshot,
                            liveGraph.flightNativeSnapshot,source.targetPath);
                    JSONArray observedRows=new JSONArray(),liveRows=new JSONArray();
                    for(PhoneObservation.Node row:observed.rows)observedRows.put(row.json());
                    for(PhoneObservation.Node row:liveGraph.rows)liveRows.put(row.json());
                    liveProof.put("retained_node_pairing",WebFlightNativeStability.compareRetained(observedRows,liveRows,
                            liveProof.getString("native_slider_path")));
                    NodeRef observedTarget=null,liveTarget=null;
                    for(PhoneObservation.Node row:observed.rows)if(source.targetPath.equals(row.nativeTreePath)){
                        if(observedTarget!=null)throw new StaleObservation("Flight新观察目标不唯一");observedTarget=observed.refs.get(row.id);
                    }
                    for(PhoneObservation.Node row:liveGraph.rows)if(source.targetPath.equals(row.nativeTreePath)){
                        if(liveTarget!=null)throw new StaleObservation("Flight最后目标不唯一");liveTarget=liveGraph.refs.get(row.id);
                    }
                    if(observedTarget==null||liveTarget==null||!source.original.node.equals(observedTarget.node)
                            ||!source.original.node.equals(liveTarget.node)
                            ||!source.original.signature.equals(observedTarget.signature)
                            ||!source.original.signature.equals(liveTarget.signature))
                        throw new StaleObservation("Flight原始目标身份或签名已变化");
                    Rect box=new Rect();source.original.node.getBoundsInScreen(box);
                    int[] region={box.left,box.top,box.right,box.bottom};
                    JSONObject windowsBefore=readRegionWindows(after,first.displayId,first.windowId,region);
                    refreshFlightTargetChain(source.background,after,source.original,source.targetPath,beforeNative);
                    if(!source.original.signature.equals(nodeSignature(source.original.node,observedChildText(source.original.node,true))))
                        throw new StaleObservation("Flight观察目标最后刷新签名已变化");
                    JSONObject windowsAfter=readRegionWindows(after,first.displayId,first.windowId,region);
                    if(!org.trillionnium.hepta.webprotocol.WebDomCanonical.same(windowsBefore,windowsAfter))
                        throw new StaleObservation("Flight观察期间交互窗口覆盖元数据变化");
                    if(requireFlightObservationCurrent(web,after,cancel)!=observed||source.closed
                            ||source.background!=backgroundFor(web.taskId)||source.scope!=scopeFor(web.taskId)
                            ||source.authorization!=authorizationFor(web.taskId)||SystemClock.elapsedRealtime()>=deadline)
                        throw new StaleObservation("Flight观察已过期或退休");
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
        },cancel,deadline);
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
            WebRegionNativeBridge bridge,Cancellation cancel)throws Exception{
        long started=SystemClock.elapsedRealtime();BackgroundSession background=backgroundFor(taskId);
        if(background==null||cancel.isCancelled()||!owns(taskId)||frame!=current||currentGraph==null)
            throw new StaleObservation("商品原生复核的任务或观察已失效");
        requireBackgroundObservation(taskId,frame);background.requireActive();bridge.requireFrame(frame);
        if(currentGraph.windowId!=bridge.windowId||currentGraph.displayId!=bridge.displayId
                ||!bridge.generation.equals(currentGraph.backgroundGeneration))
            throw new StaleObservation("商品原生复核的屏幕或窗口已变化");
        NodeRef anchorRef=currentGraph.refs.get(bridge.anchor.id),webRef=currentGraph.refs.get(bridge.nativeWebViewId);
        if(anchorRef==null||anchorRef.node!=clicked||webRef==null)
            throw new StaleObservation("商品点击没有原始原生节点引用");
        for(WebRegionNativeBridge.Role role:bridge.roles())refreshRegionRole(background,frame,role);
        if(!webRef.node.refresh()||!webRef.node.isVisibleToUser()||!webRef.node.isEnabled()
                ||!bridge.nativeWebViewSignature.equals(observedChildText(webRef.node,true).bind(baseNodeSignature(webRef.node))))
            throw new StaleObservation("原生 WebView 祖先已变化");
        requireBackgroundNodeWindow(background,frame,webRef.node);
        List<AccessibilityNodeInfo> temporary=new ArrayList<AccessibilityNodeInfo>();
        try{
            // These child positions are independently observed native relations,
            // never DOM paths or a screen-coordinate mapping.
            if(clicked.getChildCount()!=5)throw new StaleObservation("商品原生子树结构不再匹配实际样本");
            AccessibilityNodeInfo model=clicked.getChild(1);if(model!=null)temporary.add(model);
            AccessibilityNodeInfo prices=clicked.getChild(2);if(prices!=null)temporary.add(prices);
            if(model==null||prices==null||!model.refresh()||!prices.refresh()||prices.getChildCount()!=2
                    ||!"android.view.View".equals(string(prices.getClassName())))
                throw new StaleObservation("商品名称或同组价格容器已变化");
            AccessibilityNodeInfo currentPrice=prices.getChild(0);if(currentPrice!=null)temporary.add(currentPrice);
            AccessibilityNodeInfo comparisonPrice=prices.getChild(1);if(comparisonPrice!=null)temporary.add(comparisonPrice);
            List<WebRegionNativeBridge.Role> roles=bridge.roles();
            if(currentPrice==null||comparisonPrice==null||!currentPrice.refresh()||!comparisonPrice.refresh()
                    ||!model.equals(currentGraph.refs.get(roles.get(1).nodeId).node)
                    ||!currentPrice.equals(currentGraph.refs.get(roles.get(2).nodeId).node)
                    ||!comparisonPrice.equals(currentGraph.refs.get(roles.get(3).nodeId).node))
                throw new StaleObservation("同组商品四角色的原生节点身份不再一致");
            AccessibilityNodeInfo modelParent=model.getParent();if(modelParent!=null)temporary.add(modelParent);
            AccessibilityNodeInfo pricesParent=prices.getParent();if(pricesParent!=null)temporary.add(pricesParent);
            AccessibilityNodeInfo currentParent=currentPrice.getParent();if(currentParent!=null)temporary.add(currentParent);
            AccessibilityNodeInfo comparisonParent=comparisonPrice.getParent();if(comparisonParent!=null)temporary.add(comparisonParent);
            if(modelParent==null||pricesParent==null||currentParent==null||comparisonParent==null
                    ||!modelParent.refresh()||!pricesParent.refresh()||!currentParent.refresh()||!comparisonParent.refresh()
                    ||!modelParent.equals(clicked)||!pricesParent.equals(clicked)
                    ||!currentParent.equals(prices)||!comparisonParent.equals(prices))
                throw new StaleObservation("商品原生父子关系已变化");
            int distance=bridge.anchor.nativeTreePath.split("/").length-bridge.nativeWebViewPath.split("/").length;
            if(distance<1||distance>64)throw new StaleObservation("商品到原生 WebView 的祖先关系不可证明");
            AccessibilityNodeInfo cursor=clicked;
            Rect anchorBounds=new Rect();clicked.getBoundsInScreen(anchorBounds);
            for(int depth=1;depth<=distance;depth++){
                AccessibilityNodeInfo parent=cursor.getParent();if(parent!=null)temporary.add(parent);
                if(parent==null||!parent.refresh()||!parent.isVisibleToUser()||!parent.isEnabled()||parent.isPassword()
                        ||!frame.packageName.equals(string(parent.getPackageName()))||parent.getWindowId()!=frame.windowId)
                    throw new StaleObservation("商品原生祖先不可用或越出绑定窗口");
                requireBackgroundNodeWindow(background,frame,parent);
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
        JSONObject windowsBefore=readRegionWindows(frame,bridge);
        for(WebRegionNativeBridge.Role role:bridge.roles())refreshRegionRole(background,frame,role);
        JSONObject windowsAfter=readRegionWindows(frame,bridge);
        if(!org.trillionnium.hepta.webprotocol.WebDomCanonical.same(windowsBefore,windowsAfter))
            throw new StaleObservation("商品点击前的原生窗口覆盖关系已变化");
        background.requireActive();
        if(cancel.isCancelled()||!owns(taskId)||frame!=current)throw new StaleObservation("商品任务已退休");
        return new NativeRegionCheck(frame,bridge,started,SystemClock.elapsedRealtime(),windowsAfter);
    }
    private void refreshRegionRole(BackgroundSession background,PhoneObservation frame,WebRegionNativeBridge.Role role){
        NodeRef ref=currentGraph==null?null:currentGraph.refs.get(role.nodeId);
        if(ref==null||!role.nodeSignature.equals(ref.appTreeSignature)||!ref.node.refresh())
            throw new StaleObservation("商品原生角色引用已变化："+role.role);
        AccessibilityNodeInfo node=ref.node;ObservedChildText.Result child=observedChildText(node,true);
        Rect bounds=new Rect();node.getBoundsInScreen(bounds);int[] expected=role.bounds();
        if(!ref.signature.equals(nodeSignature(node,child))||!node.isVisibleToUser()||!node.isEnabled()
                ||!role.packageName.equals(string(node.getPackageName()))||!role.className.equals(string(node.getClassName()))
                ||!role.viewId.equals(string(node.getViewIdResourceName()))||!role.text.equals(string(node.getText()))
                ||!role.description.equals(string(node.getContentDescription()))||node.isClickable()!=role.clickable
                ||node.isEditable()!=role.editable||node.isScrollable()!=role.scrollable||node.isFocused()!=role.focused
                ||node.isPassword()!=role.password||bounds.left!=expected[0]||bounds.top!=expected[1]
                ||bounds.right!=expected[2]||bounds.bottom!=expected[3])
            throw new StaleObservation("商品原生角色内容或几何已变化："+role.role);
        requireBackgroundNodeWindow(background,frame,node);
    }
    /** Metadata-only; no root or text is read from any other application/window. */
    private JSONObject readRegionWindows(PhoneObservation frame,WebRegionNativeBridge bridge)throws Exception{
        return readRegionWindows(frame,bridge.displayId,bridge.windowId,bridge.anchorBounds());
    }
    private JSONObject readRegionWindows(PhoneObservation frame,int displayId,int windowId,int[] region)throws Exception{
        AccessibilityServiceInfo info=getServiceInfo();
        if(info==null||(info.flags&AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS)==0
                ||(info.getCapabilities()&AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT)==0)
            throw new StaleObservation("原生窗口覆盖元数据不可用");
        List<AccessibilityWindowInfo> windows=windowsForDisplay(displayId);
        if(windows==null)throw new StaleObservation("原生窗口集合不可用");
        try{
            if(windows.isEmpty()||windows.size()>64)throw new StaleObservation("原生窗口集合不可用");
            java.util.TreeMap<Integer,JSONObject> rows=new java.util.TreeMap<Integer,JSONObject>();
            int targetLayer=-1;Rect targetBounds=null;
            for(AccessibilityWindowInfo window:windows){
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
                Rect bounds=new Rect();window.getBoundsInScreen(bounds);
                if(Rect.intersects(bounds,anchorBounds))throw new StaleObservation("原生商品区域被其它交互窗口覆盖");
            }
            JSONArray ordered=new JSONArray();for(JSONObject row:rows.values())ordered.put(row);
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
    private static ObservedChildText.Result observedChildText(final AccessibilityNodeInfo root,final boolean refreshChildren){
        final Rect rootBounds=new Rect();root.getBoundsInScreen(rootBounds);
        final String ownerPackage=string(root.getPackageName());final int ownerWindow=root.getWindowId();
        final boolean[] staleChild={false};
        ObservedChildText.Result result=ObservedChildText.collect(root,new ObservedChildText.Reader<AccessibilityNodeInfo>(){
            public ObservedChildText.Metadata metadata(AccessibilityNodeInfo node){
                if(refreshChildren&&node!=root&&!node.refresh()){
                    staleChild[0]=true;throw new StaleObservation("后台标签子节点已不可用，需重新观察");
                }
                Rect bounds=new Rect();node.getBoundsInScreen(bounds);
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
            public AccessibilityNodeInfo child(AccessibilityNodeInfo node,int index){return node.getChild(index);}
            public void release(AccessibilityNodeInfo node){node.recycle();}
        });
        // collect() intentionally suppresses inaccessible child labels; a failed live
        // refresh additionally invalidates this background frame, not just its label.
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
