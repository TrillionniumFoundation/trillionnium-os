package org.trillionnium.hepta.local;

import android.app.KeyguardManager;
import android.content.Context;
import android.hardware.display.DisplayManager;
import android.net.Credentials;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.SystemClock;
import android.provider.Settings;
import android.system.Os;
import android.view.Display;
import org.trillionnium.hepta.background.BrokerProtocol;
import org.trillionnium.hepta.background.PublicOwnGroupPolicy;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.ProfilePrelaunchRecovery;
import org.trillionnium.hepta.background.ProfilePostlaunchRecovery;
import org.trillionnium.hepta.background.WindowOwnership;
import org.trillionnium.hepta.background.PermissionWindowObservation;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/** One explicit owner-selected display lease. Never selects or falls back to display zero. */
final class BackgroundSession {
    static final String JOURNAL="background-session.active.json";
    static final String SCHEMA="hepta.background-session.v1";
    private static final String BROKER="org.trillionnium.hepta.background.BackgroundDisplayBroker";
    private static final int REQUEST_LIMIT=16384, RESPONSE_LIMIT=65536;
    private static final long TTL_MS=540000;
    /** No package is inferred from the model or from untrusted screen text. */
    static final class Selection implements BackgroundTaskTarget.SelectionBinding {
        final String initialPackage;
        final List<String> allowedPackages;
        private final Map<String,Object> ownerSelection;
        final BackgroundTaskTarget taskTarget;
        final ProfileTarget profileTarget;
        final boolean independentProfileDisplay;
        final boolean independentPersonalDisplay;
        final org.trillionnium.hepta.background.PublicPermissionControllerUi.Locator controllerUi;
        Selection(String initial,Set<String> allowed){this(initial,allowed,null,null,null,null);}
        Selection(BackgroundTaskTarget target){this(target,false);}
        Selection(BackgroundTaskTarget target,boolean independentProfileDisplay){
            this(target,independentProfileDisplay,false);
        }
        Selection(BackgroundTaskTarget target,boolean independentProfileDisplay,boolean independentPersonalDisplay){
            this(requireExplicit(target).packageName,target.effectivePackages,target.originalInitialPackage,
                    new TreeSet<String>(target.originalPackages),target.ownerSha256,target.recognition,target,independentProfileDisplay,independentPersonalDisplay);
        }
        Selection(BackgroundTaskTarget target,boolean independentProfileDisplay,boolean independentPersonalDisplay,
                org.trillionnium.hepta.background.PublicPermissionControllerUi.Locator controllerUi){
            this(requireExplicit(target).packageName,target.effectivePackages,target.originalInitialPackage,
                    new TreeSet<String>(target.originalPackages),target.ownerSha256,target.recognition,target,
                    independentProfileDisplay,independentPersonalDisplay,controllerUi);
        }
        Selection(String initial,Set<String> allowed,String uiInitial,Set<String> uiAllowed,
                  String ownerSha,String recognition){this(initial,allowed,uiInitial,uiAllowed,ownerSha,recognition,null);}
        private Selection(String initial,Set<String> allowed,String uiInitial,Set<String> uiAllowed,
                  String ownerSha,String recognition,BackgroundTaskTarget target){
            this(initial,allowed,uiInitial,uiAllowed,ownerSha,recognition,target,false,false);
        }
        private Selection(String initial,Set<String> allowed,String uiInitial,Set<String> uiAllowed,
                  String ownerSha,String recognition,BackgroundTaskTarget target,boolean independentProfileDisplay,boolean independentPersonalDisplay){
            this(initial,allowed,uiInitial,uiAllowed,ownerSha,recognition,target,independentProfileDisplay,independentPersonalDisplay,null);
        }
        private Selection(String initial,Set<String> allowed,String uiInitial,Set<String> uiAllowed,
                  String ownerSha,String recognition,BackgroundTaskTarget target,boolean independentProfileDisplay,boolean independentPersonalDisplay,
                  org.trillionnium.hepta.background.PublicPermissionControllerUi.Locator controllerUi){
            if(allowed==null||allowed.isEmpty()||allowed.size()>6)throw new IllegalArgumentException("请选择 1 至 6 个后台任务应用");
            TreeSet<String> copy=new TreeSet<String>();
            for(String value:allowed){checkPackage(value);copy.add(value);}
            checkPackage(initial);
            if(!copy.contains(initial))throw new IllegalArgumentException("起始应用必须属于本次后台范围");
            initialPackage=initial;allowedPackages=Collections.unmodifiableList(new ArrayList<String>(copy));
            taskTarget=target;profileTarget=target==null?null:target.profileTarget;
            if(independentProfileDisplay&&(target==null||!target.explicitSelection||profileTarget==null))
                throw new IllegalArgumentException("独立后台显示需要明确选择并核验隔离资料中的应用；不会迁移个人空间应用");
            this.independentProfileDisplay=independentProfileDisplay;
            if(independentPersonalDisplay&&(independentProfileDisplay||target==null||!target.explicitSelection||profileTarget!=null
                    ||copy.size()!=1||!("com.motorola.stylus".equals(initial)||"com.xiaomi.shop".equals(initial))))
                throw new IllegalArgumentException("个人空间独立显示仅支持明确选择的备忘录或小米商城；不会迁移既有任务");
            this.independentPersonalDisplay=independentPersonalDisplay;
            if(controllerUi!=null&&(!independentProfileDisplay||target==null||profileTarget==null
                    ||profileTarget.profile.userId!=10||!ProfileTarget.CTRIP.equals(profileTarget.packageName)
                    ||ownerSha==null||!ownerSha.equals(controllerUi.ownerSha256)))
                throw new IllegalArgumentException("CONTROLLER_UI_SELECTION_UNBOUND");
            this.controllerUi=controllerUi;
            if(ownerSha==null){
                if(uiInitial!=null||uiAllowed!=null||recognition!=null)throw new IllegalArgumentException("任务范围来源不完整");
                ownerSelection=null;
            }else{
                if(!ownerSha.matches("[0-9a-f]{64}")||recognition==null||!recognition.matches("[A-Za-z0-9_.]{1,96}")
                        ||uiAllowed==null||uiAllowed.isEmpty()||uiAllowed.size()>6||copy.size()!=1)
                    throw new IllegalArgumentException("原始指令与应用范围来源不完整");
                TreeSet<String> original=new TreeSet<String>();
                for(String value:uiAllowed){checkPackage(value);original.add(value);}
                checkPackage(uiInitial);
                if(!original.contains(uiInitial)||!original.containsAll(copy))throw new IllegalArgumentException("任务应用超出已选范围");
                Map<String,Object> proof=new LinkedHashMap<String,Object>();
                proof.put("schema","hepta.owner-task-app-selection.v1");proof.put("owner_sha256",ownerSha);
                proof.put("recognition",recognition);proof.put("original_ui_initial_package",uiInitial);
                proof.put("original_ui_allowed_packages",Collections.unmodifiableList(new ArrayList<String>(original)));
                proof.put("effective_initial_package",initialPackage);proof.put("effective_allowed_packages",allowedPackages);
                proof.put("effective_scope_within_selected_apps",true);
                proof.put("effective_scope_strictly_smaller",copy.size()<original.size());
                proof.put("initial_app_changed",!initialPackage.equals(uiInitial));proof.put("package_from_model_or_screen",false);
                proof.put("grants_tool_authority",false);proof.put("changes_saved_preferences",false);
                ownerSelection=Collections.unmodifiableMap(proof);
            }
        }
        private static BackgroundTaskTarget requireExplicit(BackgroundTaskTarget target){
            if(target==null||!target.explicitSelection||!target.packageName.equals(target.originalInitialPackage))
                throw new IllegalArgumentException("本次任务缺少显式起始应用目标");
            return target;
        }
        @Override public BackgroundTaskTarget executionTarget(){return taskTarget;}
        void requireImmutableTarget(String owner){
            BackgroundTaskTarget target=requireExplicit(taskTarget);target.requireOwner(owner);
            if(!initialPackage.equals(target.packageName)
                    ||!allowedPackages.equals(new ArrayList<String>(target.effectivePackages)))
                throw new IllegalArgumentException("后台范围与不可变执行目标不一致");
        }
        void requireTaskTarget(String owner,TaskAuthorization authorization){
            requireImmutableTarget(owner);
            if(authorization==null)throw new IllegalArgumentException("执行目标缺少原始任务授权");
            authorization.requireOwner(owner);authorization.requireExecutionSelection(this);
        }
        JSONObject json()throws Exception{
            JSONObject value=new JSONObject().put("mode","background")
                .put("allowed_packages",new JSONArray(allowedPackages)).put("bootstrap_package",initialPackage)
                .put("bootstrap_source",ownerSelection==null?"owner_selected_initial_app":"owner_intent_within_explicit_ui_selection").put("bootstrap_model_issued",false)
                .put("main_display_fallback",false).put("home_allowed",false);
            if(ownerSelection!=null)value.put("owner_task_selection",new JSONObject(ownerSelection));
            if(profileTarget!=null)value.put("profile_target_wire",profileTarget.wire()).put("profile_target_sha256",profileTarget.sha256);
            if(independentProfileDisplay)value.put("display_scope_mode","public_own_group_no_credentials_v1")
                    .put("display_scope_mode_source","immutable_start_selection").put("display_scope_mode_grants_authority",false);
            if(independentPersonalDisplay)value.put("display_scope_mode","public_own_group_personal_no_credentials_v1")
                    .put("display_scope_mode_source","immutable_start_selection").put("display_scope_mode_grants_authority",false);
            return value;
        }
    }
    interface ReconciliationCheck {void check()throws Exception;}
    interface BusinessReconciliationCheck extends ReconciliationCheck {void checkBusiness(String task,String owner)throws Exception;}
    static final class Cleanup {
        final boolean known;final JSONObject evidence;
        final ProfileRecoveryClient.Receipt prelaunchRecovery;
        final ProfilePostlaunchRecoveryClient.Receipt postlaunchRecovery;
        final PublicProfileRecoveryClient.Receipt publicProfileRecovery;
        final PublicPersonalNotesRecoveryClient.Receipt personalNotesRecovery;
        final PublicProfileBusinessRecoveryClient.Receipt businessRecovery;
        private Cleanup(boolean known,JSONObject evidence,PublicProfileBusinessRecoveryClient.Receipt business,boolean typed){
            if(!typed||business==null)throw new IllegalArgumentException("typed business receipt required");
            this.known=known;this.evidence=evidence;prelaunchRecovery=null;postlaunchRecovery=null;publicProfileRecovery=null;personalNotesRecovery=null;businessRecovery=business;
        }
        Cleanup(boolean known,JSONObject evidence){this(known,evidence,null,null);}
        private Cleanup(boolean known,JSONObject evidence,ProfileRecoveryClient.Receipt receipt){
            this(known,evidence,receipt,null);
        }
        private Cleanup(boolean known,JSONObject evidence,ProfileRecoveryClient.Receipt prelaunch,
                ProfilePostlaunchRecoveryClient.Receipt postlaunch){
            this(known,evidence,prelaunch,postlaunch,null);
        }
        private Cleanup(boolean known,JSONObject evidence,ProfileRecoveryClient.Receipt prelaunch,
                ProfilePostlaunchRecoveryClient.Receipt postlaunch,PublicProfileRecoveryClient.Receipt publicProfile){
            this(known,evidence,prelaunch,postlaunch,publicProfile,null);
        }
        private Cleanup(boolean known,JSONObject evidence,ProfileRecoveryClient.Receipt prelaunch,
                ProfilePostlaunchRecoveryClient.Receipt postlaunch,PublicProfileRecoveryClient.Receipt publicProfile,
                PublicPersonalNotesRecoveryClient.Receipt personalNotes){
            this.known=known;this.evidence=evidence;prelaunchRecovery=prelaunch;postlaunchRecovery=postlaunch;
            publicProfileRecovery=publicProfile;personalNotesRecovery=personalNotes;businessRecovery=null;
        }
    }
    final String taskId,generation,socketName,displayName,ownerSha256;
    final Selection selection;
    final long createdElapsed,expiresElapsed;
    private final Context context;
    private final QualificationScopeConfig.FilesRoot filesRoot;
    private final File journal;
    private final int bootCount;
    private final PublicOwnGroupPolicy.Scope publicOwnGroupScope;
    private final Object publicScopeOwner=new Object(),publicScopeIo=new Object();
    private final PublicOwnGroupPolicy.LiveLease publicScopeLease;
    private volatile PublicOwnGroupPolicy.Readback publicScopeReadback;
    private volatile String state="INITIAL";
    private volatile int displayId=-1;
    private volatile boolean retired,spawnAttempted,bootstrapDispatched,cleanupConfirmed;
    private volatile JSONObject lastResponse;
    private volatile CalendarDateRpcTrace calendarDateRpcTrace;
    private volatile JSONObject appDisplayReadback;
    private volatile JSONObject profileCleanupEvidence;
    private volatile JSONObject personalNotesCleanupEvidence;
    private volatile boolean profileLaunchAttempted;
    private volatile boolean permissionPreparing;
    private final java.util.IdentityHashMap<WindowOwnership,Boolean> profileProofs=new java.util.IdentityHashMap<WindowOwnership,Boolean>();
    private final java.util.IdentityHashMap<PermissionWindowObservation,Boolean> permissionProofs=new java.util.IdentityHashMap<PermissionWindowObservation,Boolean>();
    private Process brokerProcess;
    private volatile boolean brokerExitObserved;
    private volatile Integer brokerExitCode;
    private BrokerOutput brokerOutput;
    private Thread brokerOutputThread;

    BackgroundSession(Context context,String taskId,String owner,Selection selection,
                      QualificationScopeConfig.FilesRoot filesRoot)throws Exception{
        this(context,taskId,owner,selection,filesRoot,false);
    }
    /** Explicit ordinary-Start display mode. The immutable selection captures the
     * visible saved choice; real root and App display proofs grant each live scope. */
    static BackgroundSession experimentalPublicOwnGroup(Context context,String taskId,String owner,Selection selection,
            QualificationScopeConfig.FilesRoot filesRoot)throws Exception{
        if(selection==null)throw new IllegalArgumentException("explicit task selection required");
        selection.requireImmutableTarget(owner);
        return new BackgroundSession(context,taskId,owner,selection,filesRoot,true);
    }
    private BackgroundSession(Context context,String taskId,String owner,Selection selection,
                      QualificationScopeConfig.FilesRoot filesRoot,boolean publicOwnGroup)throws Exception{
        if(taskId==null||!taskId.matches("[0-9a-f]{32}")||selection==null)throw new IllegalArgumentException("后台会话身份缺失");
        this.context=context.getApplicationContext();this.taskId=taskId;this.selection=selection;this.filesRoot=filesRoot;
        filesRoot.unchanged(context);journal=new File(filesRoot.path,JOURNAL);
        if(MobiMindPrivateFiles.exists(journal))throw new IllegalStateException("上一次后台空间尚未确认释放，请先清理后台空间");
        generation=UUID.randomUUID().toString();socketName="hepta-bg-"+generation;displayName=socketName;
        ownerSha256=HeptaAccessibilityService.sha(owner.getBytes(StandardCharsets.UTF_8));
        createdElapsed=SystemClock.elapsedRealtime();expiresElapsed=createdElapsed+TTL_MS;bootCount=readBootCount(context);
        publicOwnGroupScope=publicOwnGroup?new PublicOwnGroupPolicy.Scope(taskId,ownerSha256,generation,android.os.Process.myUid(),
                profileTarget(),createdElapsed,expiresElapsed,bootCount):null;
        publicScopeLease=publicOwnGroupScope==null?null:new PublicOwnGroupPolicy.LiveLease(publicScopeOwner,publicOwnGroupScope);
    }
    boolean allows(String pkg){return selection.allowedPackages.contains(pkg);}
    ProfileTarget profileTarget(){return selection.profileTarget;}
    private int protocolVersion(){return publicOwnGroupScope==null?(profileTarget()==null?BrokerProtocol.VERSION:BrokerProtocol.PROFILE_VERSION)
            :(profileTarget()==null?BrokerProtocol.PUBLIC_OWN_GROUP_VERSION:BrokerProtocol.PUBLIC_OWN_GROUP_PROFILE_VERSION);}
    boolean usesExperimentalPublicOwnGroup(){return publicOwnGroupScope!=null;}
    private boolean requiresPersonalNotesRetirement(){return publicOwnGroupScope!=null&&profileTarget()==null
            &&selection.allowedPackages.size()==1&&"com.motorola.stylus".equals(selection.initialPackage);}
    private JSONObject request(String operation,String pkg,long deadline)throws Exception{
        JSONObject value=new JSONObject().put("version",protocolVersion()).put("request_id",UUID.randomUUID().toString())
                .put("generation",generation).put("deadline_elapsed_ms",deadline).put("op",operation);
        if(pkg!=null)value.put("package",pkg);
        if(profileTarget()!=null)value.put("target_sha256",profileTarget().sha256);
        if(publicOwnGroupScope!=null)value.put("display_scope_sha256",publicOwnGroupScope.sha256);
        return value;
    }
    void verifyProfileInstallation()throws Exception{
        if(profileTarget()==null)throw new IllegalStateException("profile target required");
        verifyRemote();
    }
    interface InitializationHandler {
        void prepare(BackgroundSession session,long originalDeadline,HeptaAccessibilityService.Cancellation cancel)throws Exception;
    }
    void requirePermissionPreparationActive(){
        requireActive();
        if(!permissionPreparing||profileTarget()==null||!ProfileTarget.CTRIP.equals(profileTarget().packageName)||!profileLaunchAttempted)
            throw new IllegalStateException("同一隔离用户的权限初始化尚未开始或已经结束");
    }
    String readPreparation(HeptaAccessibilityService.Cancellation cancel,long originalDeadline)throws Exception{
        JSONObject response=permissionRpc("prepare_state",null,-1,-1,cancel,originalDeadline);
        String value=response.getString("profile_permission_preparation_state");
        if(!java.util.Arrays.asList("APP_READY","PERMISSION_PENDING","WAITING").contains(value))throw new IOException("权限初始化状态不可验证");
        return value;
    }
    PermissionWindowObservation verifyPermissionWindow(int windowId,int observedTaskId,HeptaAccessibilityService.Cancellation cancel,long originalDeadline)throws Exception{
        requirePermissionPreparationActive();long begun=SystemClock.elapsedRealtime();
        long deadline=Math.min(expiresElapsed,boundedActionDeadline(originalDeadline,7000));
        JSONObject response=permissionRpc("permission_window",profileTarget().packageName,windowId,observedTaskId,cancel,deadline);
        PermissionWindowObservation proof=PermissionWindowObservation.fromWire(response.getString("permission_window_wire"),profileTarget());
        long now=SystemClock.elapsedRealtime();proof.requireMatches(profileTarget(),generation,displayId,windowId,observedTaskId,now);
        proof.requireMode(publicOwnGroupScope,publicScopeReadback,now);
        if(proof.observedElapsedMs<begun||proof.expiresElapsedMs>deadline||cancel.isCancelled())throw new IOException("权限读取超过原始请求或任务已停止");
        synchronized(permissionProofs){
            if(permissionProofs.size()>=BrokerProtocol.MAX_PROFILE_REQUEST_IDS)throw new IOException("权限读取凭据数量超限");
            permissionProofs.put(proof,Boolean.TRUE);
        }
        return proof;
    }
    void requirePermissionWindow(PermissionWindowObservation proof,long now){
        requirePermissionPreparationActive();
        synchronized(permissionProofs){if(proof==null||!permissionProofs.containsKey(proof))
            throw new IllegalStateException("权限窗口并非来自当前后台服务的实际已认证读取");}
        proof.requireMatches(profileTarget(),generation,displayId,proof.windowId,proof.taskId,now);
        proof.requireMode(publicOwnGroupScope,publicScopeReadback,now);
    }
    private JSONObject permissionRpc(String op,String pkg,int window,int task,HeptaAccessibilityService.Cancellation cancel,long originalDeadline)throws Exception{
        requirePermissionPreparationActive();
        if(cancel==null||cancel.isCancelled())throw new IOException("权限初始化已停止");
        long deadline=Math.min(expiresElapsed,boundedActionDeadline(originalDeadline,7000));
        JSONObject request=request(op,pkg,deadline);
        if("permission_window".equals(op))request.put("window_id",window).put("task_id",task);
        JSONObject response=exchangeForSession(request,7500,cancel);accept(response,true);requirePermissionPreparationActive();
        requireControllerUiObservation(response);
        if(!"prepare_done".equals(op)&&!response.getBoolean("profile_permission_preparing"))throw new IOException("后台权限初始化阶段不一致");
        return response;
    }
    private void finishPermissionPreparation(HeptaAccessibilityService.Cancellation cancel,long originalDeadline)throws Exception{
        JSONObject response=permissionRpc("prepare_done",null,-1,-1,cancel,originalDeadline);
        if(response.getBoolean("profile_permission_preparing")||!"COMPLETE".equals(response.getString("profile_permission_preparation_state")))
            throw new IOException("普通应用窗口尚未重新通过验证");
        permissionPreparing=false;synchronized(permissionProofs){permissionProofs.clear();}
    }
    /** Historical read-only RPC provenance, already unregistered/drained; never a live capture or input permission. */
    static final class CalendarWindowProbeReceipt {
        private final BackgroundSession source;
        private final String requestSnapshot,responseSnapshot;
        final String requestId;
        final int windowId,observedTaskId;
        final long receivedElapsedMs,originalDeadlineElapsedMs;
        private CalendarWindowProbeReceipt(BackgroundSession source,JSONObject request,JSONObject response,
                int window,int task,long received,long deadline)throws Exception{
            this.source=source;requestSnapshot=request.toString();responseSnapshot=response.toString();requestId=request.getString("request_id");
            windowId=window;observedTaskId=task;receivedElapsedMs=received;originalDeadlineElapsedMs=deadline;
        }
        boolean belongsTo(BackgroundSession actual){return actual!=null&&source==actual;}
        boolean grantsDispatch(){return false;}
        JSONObject requestEvidence()throws Exception{return new JSONObject(requestSnapshot);}
        JSONObject evidence()throws Exception{return new JSONObject(responseSnapshot);}
    }
    /** Worker-only ROM read, through the existing authenticated root socket. No node/input authority. */
    CalendarWindowProbeReceipt readCalendarWindowProbe(int windowId,int observedTaskId,
            HeptaAccessibilityService.Cancellation cancel,long originalDeadline)throws Exception{
        ProfileTarget target=profileTarget();
        if(publicOwnGroupScope==null||target==null||!ProfileTarget.CTRIP.equals(target.packageName)
                ||windowId<0||observedTaskId<=0||cancel==null||cancel.isCancelled()
                ||android.os.Looper.myLooper()==android.os.Looper.getMainLooper())
            throw new IOException("CALENDAR_PROBE_CLIENT_ADMISSION");
        final long began=SystemClock.elapsedRealtime();
        final long deadline=Math.min(expiresElapsed,boundedActionDeadline(originalDeadline,4000));
        synchronized(publicScopeIo){
            requireAdmissionActive();
            JSONObject request=request("calendar_probe",target.packageName,deadline)
                    .put("window_id",windowId).put("task_id",observedTaskId);
            JSONObject response=exchangeForSession(request,4000,cancel);accept(response,true);
            requireAdmissionActive();long now=SystemClock.elapsedRealtime();
            if(cancel.isCancelled()||now>=deadline)throw new IOException("CALENDAR_PROBE_CLIENT_DEADLINE");
            JSONObject p=response.getJSONObject("calendar_window_probe"),isolation=p.getJSONObject("isolation"),life=p.getJSONObject("listener_lifecycle");
            long entered=strictLong(p,"entered_elapsed_ms"),finished=strictLong(p,"read_finished_elapsed_ms"),qualified=strictLong(p,"qualified_elapsed_ms");
            if(!"hepta.calendar-window-probe.v1".equals(p.getString("schema"))
                    ||!request.getString("request_id").equals(p.getString("request_id"))||!generation.equals(p.getString("generation"))
                    ||!target.sha256.equals(p.getString("target_sha256"))||!publicOwnGroupScope.sha256.equals(p.getString("display_scope_sha256"))
                    ||strictLong(p,"original_request_deadline_elapsed_ms")!=deadline||strictLong(p,"probe_deadline_elapsed_ms")!=deadline
                    ||entered<began||finished<entered||qualified<finished||qualified>now
                    ||!Boolean.TRUE.equals(p.get("qualified"))||!Boolean.FALSE.equals(p.get("grants_dispatch"))
                    ||!Boolean.FALSE.equals(p.get("dispatched"))||!Boolean.FALSE.equals(p.get("calendar_date_effect_integrated"))||strictInt(p,"input_attempts")!=0
                    ||!"readonly_window_channel_isolation_verified".equals(p.getString("phase")))
                throw new IOException("CALENDAR_PROBE_CLIENT_RECEIPT");
            if(!"hepta.input-channel-isolation-readonly.v1".equals(isolation.getString("schema"))
                    ||strictInt(isolation,"display_id")!=displayId||strictInt(isolation,"full_uid")!=target.fullUid
                    ||strictInt(isolation,"target_profile_user_id")!=target.profile.userId
                    ||strictInt(isolation,"accessibility_namespace_user_id")!=target.profile.parentUserId
                    ||!target.packageName.equals(isolation.getString("package"))||strictInt(isolation,"accessibility_window_id")!=windowId
                    ||strictInt(isolation,"observed_task_id")!=observedTaskId||strictInt(isolation,"actual_window_token_match_count")!=1
                    ||strictInt(isolation,"cross_display_input_or_window_token_aliases")!=0
                    ||!Boolean.FALSE.equals(isolation.get("grants_dispatch"))||strictInt(isolation,"input_attempts")!=0)
                throw new IOException("CALENDAR_PROBE_CLIENT_WINDOW_BINDING");
            if(!"hepta.window-infos-listener-lifecycle.v1".equals(life.getString("schema"))
                    ||!Boolean.TRUE.equals(life.get("registration_returned"))||!Boolean.TRUE.equals(life.get("retired"))
                    ||!Boolean.TRUE.equals(life.get("unregister_returned"))||!Boolean.TRUE.equals(life.get("local_callbacks_drained"))
                    ||!Boolean.FALSE.equals(life.get("retains_current_census"))||!Boolean.FALSE.equals(life.get("register_cache_grants_currentness"))
                    ||strictInt(life,"callbacks_in_flight")!=0||strictLong(life,"callback_arrivals")<=0
                    ||strictLong(life,"callback_arrivals")!=strictLong(life,"callback_finishes")
                    ||!Boolean.FALSE.equals(life.get("grants_dispatch"))||strictInt(life,"input_attempts")!=0)
                throw new IOException("CALENDAR_PROBE_CLIENT_DRAIN_UNKNOWN");
            return new CalendarWindowProbeReceipt(this,request,response,windowId,observedTaskId,now,deadline);
        }
    }

    /** Actual authenticated pair acknowledgement, not a verified date or another action permission. */
    static final class CalendarDateInputReceipt {
        private final BackgroundSession source;
        private final HeptaAccessibilityService.CalendarInputAttempt sourceAttempt;
        private final String requestSnapshot,responseSnapshot;
        final String requestId;
        final long receivedElapsedMs,originalDeadlineElapsedMs,brokerDeadlineElapsedMs;
        private CalendarDateInputReceipt(BackgroundSession source,HeptaAccessibilityService.CalendarInputAttempt attempt,
                JSONObject request,JSONObject response,long received,long original,long brokerDeadline)throws Exception{
            this.source=source;sourceAttempt=attempt;requestSnapshot=request.toString();responseSnapshot=response.toString();
            requestId=request.getString("request_id");receivedElapsedMs=received;originalDeadlineElapsedMs=original;
            brokerDeadlineElapsedMs=brokerDeadline;
        }
        boolean belongsTo(BackgroundSession actual,HeptaAccessibilityService.CalendarInputAttempt attempt){
            return actual!=null&&attempt!=null&&source==actual&&sourceAttempt==attempt;
        }
        boolean grantsAdditionalDispatch(){return false;}
        boolean independentlyVerifiesDate(){return false;}
        JSONObject requestEvidence()throws Exception{return new JSONObject(requestSnapshot);}
        JSONObject evidence()throws Exception{return new JSONObject(responseSnapshot);}
    }
    /** Attempt-scoped transport facts only. Never consulted as admission or effect authority. */
    private static final class CalendarDateRpcTrace {
        private final JSONObject value;
        private CalendarDateRpcTrace(JSONObject request,long original,long began)throws Exception{
            value=new JSONObject().put("schema","hepta.calendar-date-client-transport.v1")
                    .put("request",new JSONObject(request.toString())).put("original_action_deadline_elapsed_ms",original)
                    .put("began_elapsed_ms",began).put("socket_connected",false).put("root_peer_verified",false)
                    .put("request_write_attempted",false).put("request_write_completed",false)
                    .put("wire_payload_received",false).put("wire_response_validated",false).put("receipt_accepted",false)
                    .put("automatic_retry",false).put("serialized_trace_grants_authority",false);
        }
        synchronized void mark(String key)throws Exception{value.put(key,true).put(key+"_elapsed_ms",SystemClock.elapsedRealtime());}
        synchronized void payload(byte[] actual)throws Exception{value.put("wire_payload_received",true)
                .put("wire_payload_bytes",actual.length).put("wire_payload_sha256",HeptaAccessibilityService.sha(actual))
                .put("wire_payload_received_elapsed_ms",SystemClock.elapsedRealtime());}
        synchronized void response(JSONObject actual)throws Exception{value.put("wire_response_validated",true)
                .put("wire_response_validated_elapsed_ms",SystemClock.elapsedRealtime()).put("actual_response",new JSONObject(actual.toString()));}
        synchronized void failure(Exception error)throws Exception{value.put("failure",HeptaAccessibilityService.message(error))
                .put("finished_elapsed_ms",SystemClock.elapsedRealtime());}
        synchronized JSONObject evidence()throws Exception{return new JSONObject(value.toString());}
    }

    /** Only the actual HA ActionWork/Slot may supply this private one-use attempt. */
    CalendarDateInputReceipt performCalendarDate(HeptaAccessibilityService.CalendarInputAttempt attempt,
            HeptaAccessibilityService.Cancellation cancel)throws Exception{
        if(attempt==null||cancel==null||cancel.isCancelled()
                ||android.os.Looper.myLooper()==android.os.Looper.getMainLooper())
            throw new IOException("CALENDAR_DATE_CLIENT_ADMISSION");
        final long began=SystemClock.elapsedRealtime();
        // This consumes the one RPC opportunity. No error below restores it.
        Map<String,Object> fields=attempt.beginBrokerCall(this,cancel);
        Set<String> expected=new TreeSet<String>(java.util.Arrays.asList("package","window_id","task_id","deadline_elapsed_ms",
                "owner_task_id","goal_sha256","date","observation_id","screen_sha256","permit_sha256","attempt_record_sha256",
                "display_width","display_height","display_rotation","left","top","right","bottom"));
        if(fields==null||!fields.keySet().equals(expected))throw new IOException("CALENDAR_DATE_ATTEMPT_FIELDS");
        final ProfileTarget target=profileTarget();
        if(publicOwnGroupScope==null||target==null||!ProfileTarget.CTRIP.equals(target.packageName)
                ||!target.packageName.equals(fields.get("package"))||!taskId.equals(fields.get("owner_task_id"))
                ||!publicOwnGroupScope.taskId.equals(taskId))
            throw new IOException("CALENDAR_DATE_ATTEMPT_SCOPE");
        final JSONObject data=new JSONObject(fields);
        final long originalDeadline=strictLong(data,"deadline_elapsed_ms");
        final long deadline=Math.min(expiresElapsed,boundedActionDeadline(originalDeadline,4000));
        final int window=strictInt(data,"window_id"),task=strictInt(data,"task_id");
        if(task<=0)throw new IOException("CALENDAR_DATE_ATTEMPT_TASK");
        JSONObject request=request("calendar_date",target.packageName,deadline).put("window_id",window).put("task_id",task);
        for(String key:expected)if(!java.util.Arrays.asList("package","window_id","task_id","deadline_elapsed_ms").contains(key))
            request.put(key,data.get(key));
        // Exact wire value validation does not construct the HA attempt or grant permission.
        BrokerProtocol.Request.parse(request.toString().getBytes(StandardCharsets.UTF_8));
        CalendarDateRpcTrace trace=new CalendarDateRpcTrace(request,originalDeadline,began);
        calendarDateRpcTrace=trace;
        synchronized(publicScopeIo){
            try{
                requireAdmissionActive();
                JSONObject response=exchangeCalendarForSession(request,4000,cancel,attempt,trace);
                accept(response,true);requireAdmissionActive();long now=SystemClock.elapsedRealtime();
                if(cancel.isCancelled()||now>=deadline)throw new IOException("CALENDAR_DATE_CLIENT_DEADLINE");
                requireCalendarDateReply(request,response,data,target,window,task,began,deadline,now);
                trace.mark("receipt_accepted");
                return new CalendarDateInputReceipt(this,attempt,request,response,now,originalDeadline,deadline);
            }catch(Exception failure){
                retirePublicScope();
                try{trace.failure(failure);}catch(Exception unavailable){/* Preserve the first transport/authority outcome. */}
                throw failure;
            }
        }
    }

    private void requireCalendarDateReply(JSONObject request,JSONObject response,JSONObject data,ProfileTarget target,
            int window,int task,long began,long deadline,long now)throws Exception{
        JSONObject p=response.getJSONObject("calendar_date_input"),isolation=p.getJSONObject("isolation"),life=p.getJSONObject("listener_lifecycle");
        if(!Boolean.TRUE.equals(response.get("dispatched"))
                ||!"hepta.calendar-date-input-attempt.v1".equals(p.getString("schema"))
                ||!request.getString("request_id").equals(p.getString("request_id"))||!generation.equals(p.getString("generation"))
                ||strictInt(p,"display_id")!=displayId||strictInt(p,"target_full_uid")!=target.fullUid
                ||!target.sha256.equals(p.getString("profile_target_sha256"))
                ||!publicOwnGroupScope.sha256.equals(p.getString("display_scope_sha256"))
                ||strictLong(p,"original_request_deadline_elapsed_ms")!=deadline||strictLong(p,"effect_deadline_elapsed_ms")!=deadline
                ||!Boolean.TRUE.equals(p.get("effect_route_integrated"))||!Boolean.TRUE.equals(p.get("attempt_consumed"))
                ||!Boolean.TRUE.equals(p.get("down_attempted"))||!Boolean.TRUE.equals(p.get("down_returned_true"))
                ||!Boolean.TRUE.equals(p.get("up_attempted"))||!Boolean.TRUE.equals(p.get("up_returned_true"))
                ||!Boolean.TRUE.equals(p.get("input_pair_accepted"))||!Boolean.FALSE.equals(p.get("cancel_attempted"))
                ||!Boolean.FALSE.equals(p.get("second_down_attempted"))||!Boolean.FALSE.equals(p.get("date_independently_verified"))
                ||!Boolean.FALSE.equals(p.get("business_completion_verified"))
                ||!Boolean.FALSE.equals(p.get("dispatcher_device_id_isolation_claimed"))
                ||!"input_pair_accepted_date_unverified".equals(p.getString("phase"))
                ||p.has("first_failure")||p.has("listener_close_failure"))
            throw new IOException("CALENDAR_DATE_CLIENT_RECEIPT");
        for(String key:new String[]{"owner_task_id","goal_sha256","date","observation_id","screen_sha256","permit_sha256","attempt_record_sha256"})
            if(!data.get(key).equals(p.get(key)))throw new IOException("CALENDAR_DATE_CLIENT_INTENT_BINDING");
        JSONArray rectangle=p.getJSONArray("rectangle");
        if(rectangle.length()!=4)throw new IOException("CALENDAR_DATE_CLIENT_RECT");
        String[] edges={"left","top","right","bottom"};
        for(int i=0;i<4;i++){Object n=rectangle.get(i);
            if((!(n instanceof Integer)&&!(n instanceof Long))||((Number)n).longValue()!=strictInt(data,edges[i]))
                throw new IOException("CALENDAR_DATE_CLIENT_RECT");}
        long entered=strictLong(p,"entered_elapsed_ms"),consumed=strictLong(p,"consumed_elapsed_ms"),
                down=strictLong(p,"down_attempted_elapsed_ms"),downReturned=strictLong(p,"down_returned_elapsed_ms"),
                up=strictLong(p,"up_attempted_elapsed_ms"),upReturned=strictLong(p,"up_returned_elapsed_ms"),
                finished=strictLong(p,"finished_elapsed_ms");
        if(entered<began||consumed<entered||down<consumed||downReturned<down||up<downReturned
                ||upReturned<up||finished<upReturned||finished>now||now>=deadline
                ||strictLong(p,"down_time_uptime_ms")<0||strictLong(p,"up_time_uptime_ms")<strictLong(p,"down_time_uptime_ms")
                ||strictLong(p,"requested_device_id")!=-1||strictInt(p,"injection_mode_platform_value")!=1)
            throw new IOException("CALENDAR_DATE_CLIENT_CLOCK_OR_MODE");
        int flag=strictInt(p,"no_focus_change_platform_value");
        if(flag<=0||(flag&(flag-1))!=0)throw new IOException("CALENDAR_DATE_CLIENT_NO_FOCUS_FLAG");
        for(String key:new String[]{"display_before","display_after"}){
            JSONObject geometry=p.getJSONObject(key);
            if(!displayName.equals(geometry.getString("display_name"))||strictInt(geometry,"display_id")!=displayId
                    ||!"android.view.Display.getRealMetrics".equals(geometry.getString("metrics_source"))||strictInt(geometry,"width")!=strictInt(data,"display_width")
                    ||strictInt(geometry,"height")!=strictInt(data,"display_height")||strictInt(geometry,"rotation")!=strictInt(data,"display_rotation"))
                throw new IOException("CALENDAR_DATE_CLIENT_GEOMETRY");
        }
        WindowOwnership before=calendarDateWindowEvidence(p.getJSONObject("owned_window_before"),target,window,task,began,deadline);
        WindowOwnership after=calendarDateWindowEvidence(p.getJSONObject("owned_window_after"),target,window,task,began,deadline);
        after.requireMatches(target,generation,displayId,window,task,down);
        after.requireMatches(target,generation,displayId,window,task,up);
        if(before.taskId!=after.taskId||before.parentTaskId!=after.parentTaskId||!before.taskTokenId.equals(after.taskTokenId))
            throw new IOException("CALENDAR_DATE_CLIENT_OWNED_TASK_CHANGED");
        if(!"hepta.input-channel-isolation-readonly.v1".equals(isolation.getString("schema"))
                ||strictInt(isolation,"display_id")!=displayId||strictInt(isolation,"full_uid")!=target.fullUid
                ||strictInt(isolation,"target_profile_user_id")!=target.profile.userId
                ||strictInt(isolation,"accessibility_namespace_user_id")!=target.profile.parentUserId
                ||!target.packageName.equals(isolation.getString("package"))||strictInt(isolation,"accessibility_window_id")!=window
                ||strictInt(isolation,"observed_task_id")!=task||strictInt(isolation,"actual_window_token_match_count")!=1
                ||strictInt(isolation,"cross_display_input_or_window_token_aliases")!=0
                ||!Boolean.FALSE.equals(isolation.get("grants_dispatch"))||strictInt(isolation,"input_attempts")!=0)
            throw new IOException("CALENDAR_DATE_CLIENT_ISOLATION");
        if(!"hepta.window-infos-listener-lifecycle.v1".equals(life.getString("schema"))
                ||!Boolean.TRUE.equals(life.get("registration_returned"))||!Boolean.TRUE.equals(life.get("retired"))
                ||!Boolean.TRUE.equals(life.get("unregister_returned"))||!Boolean.TRUE.equals(life.get("local_callbacks_drained"))
                ||!Boolean.FALSE.equals(life.get("retains_current_census"))||!Boolean.FALSE.equals(life.get("register_cache_grants_currentness"))
                ||strictInt(life,"callbacks_in_flight")!=0||strictLong(life,"callback_arrivals")<=0
                ||strictLong(life,"callback_arrivals")!=strictLong(life,"callback_finishes")
                ||!Boolean.FALSE.equals(life.get("grants_dispatch"))||strictInt(life,"input_attempts")!=0)
            throw new IOException("CALENDAR_DATE_CLIENT_DRAIN_UNKNOWN");
    }

    /** Reconstruct only a historical value for receipt checking; do not register it as a live profile proof. */
    private WindowOwnership calendarDateWindowEvidence(JSONObject value,ProfileTarget target,int window,int task,
            long began,long deadline)throws Exception{
        if(!WindowOwnership.SCHEMA.equals(value.getString("schema"))||!WindowOwnership.SOURCE.equals(value.getString("source"))
                ||!target.sha256.equals(value.getString("target_identity_sha256"))
                ||!Boolean.FALSE.equals(value.get("serialized_token_is_authority"))||!Boolean.FALSE.equals(value.get("grants_action_authority")))
            throw new IOException("CALENDAR_DATE_CLIENT_WINDOW");
        WindowOwnership proof=new WindowOwnership(target,value.getString("generation"),strictInt(value,"display_id"),
                strictInt(value,"window_id"),strictInt(value,"task_id"),strictInt(value,"parent_task_id"),
                value.getString("task_token_id"),value.getString("proof_id"),strictInt(value,"user_id"),
                strictLong(value,"user_serial"),strictInt(value,"full_uid"),strictLong(value,"observed_elapsed_ms"),strictLong(value,"expires_elapsed_ms"));
        if(!proof.sha256.equals(value.getString("proof_sha256"))||proof.observedElapsedMs<began||proof.expiresElapsedMs>deadline)
            throw new IOException("CALENDAR_DATE_CLIENT_WINDOW_BINDING");
        proof.requireMatches(target,generation,displayId,window,task,proof.observedElapsedMs);
        return proof;
    }

    WindowOwnership verifyProfileWindow(int windowId,int observedTaskId,HeptaAccessibilityService.Cancellation cancel,long originalDeadline)throws Exception{
        ProfileTarget target=profileTarget();if(target==null)throw new IllegalStateException("profile target required");
        requireActive();if(cancel==null||cancel.isCancelled())throw new IOException("profile observation cancelled");
        long begun=SystemClock.elapsedRealtime(),deadline=Math.min(expiresElapsed,boundedActionDeadline(originalDeadline,4000));
        JSONObject request=request("window",target.packageName,deadline).put("window_id",windowId).put("task_id",observedTaskId);
        JSONObject response=exchangeForSession(request,4500,cancel);accept(response,true);requireActive();
        WindowOwnership proof=WindowOwnership.fromWire(response.getString("window_ownership_wire"),target);
        long now=SystemClock.elapsedRealtime();proof.requireMatches(target,generation,displayId,windowId,observedTaskId,now);
        if(proof.observedElapsedMs<begun||proof.expiresElapsedMs>deadline||cancel.isCancelled())
            throw new IOException("profile window proof exceeded original request");
        synchronized(profileProofs){
            // Retain the actual received objects for historical frame provenance.
            // Expiry remains enforced separately by requireProfileWindow on live use.
            if(profileProofs.size()>=BrokerProtocol.MAX_PROFILE_REQUEST_IDS)throw new IOException("profile proof bound");
            profileProofs.put(proof,Boolean.TRUE);
        }
        return proof;
    }
    void requireProfileWindow(WindowOwnership proof,int windowId,int observedTaskId,long now){
        requireActive();
        if(profileTarget()==null||proof==null)throw new IllegalStateException("actual profile window proof missing");
        synchronized(profileProofs){if(!profileProofs.containsKey(proof))throw new IllegalStateException("profile proof was not obtained from this live broker");}
        proof.requireMatches(profileTarget(),generation,displayId,windowId,observedTaskId,now);
    }
    /** Historical provenance only; never renews a live window or permits an effect. */
    void requireHistoricalProfileWindow(WindowOwnership proof,int windowId,int observedTaskId,long capturedAt){
        if(profileTarget()==null||proof==null||capturedAt>SystemClock.elapsedRealtime())
            throw new IllegalStateException("actual historical profile proof missing");
        synchronized(profileProofs){if(!profileProofs.containsKey(proof))
            throw new IllegalStateException("historical proof was not received from this session broker");}
        proof.requireMatches(profileTarget(),generation,displayId,windowId,observedTaskId,capturedAt);
    }
    int displayId(){return displayId;}
    boolean released(){return "RELEASED".equals(state)&&retired&&cleanupConfirmed;}
    synchronized boolean prelaunchRecoveryEligible(){return publicOwnGroupScope==null&&profileTarget()!=null&&retired&&!profileLaunchAttempted&&displayId==-1
            &&("INITIAL".equals(state)||"CLEANUP_UNKNOWN".equals(state));}
    synchronized boolean postlaunchRecoveryEligible(){return publicOwnGroupScope==null&&profileTarget()!=null&&retired&&profileLaunchAttempted&&displayId>0
            &&"CLEANUP_UNKNOWN".equals(state);}
    /** This is a distinct drained public lease, not an extension of private proof authority. */
    synchronized boolean publicProfileRecoveryEligible(){return publicProfilePostlaunchRecoveryEligible()||publicOwnGroupScope!=null&&profileTarget()!=null&&profileTarget().profile.userId==10
            &&retired&&!profileLaunchAttempted&&!bootstrapDispatched&&!permissionPreparing&&displayId==-1
            &&brokerExitObserved&&brokerExitCode!=null&&"CLEANUP_UNKNOWN".equals(state);}
    /** A failed prepare_done can leave its stage bit set after the controller and
     * broker have both exited. Actual permission/action/observation worker gates
     * remain in the service and client; this predicate grants no input authority. */
    private boolean publicProfilePostlaunchRecoveryEligible(){return publicOwnGroupScope!=null&&profileTarget()!=null
            &&profileTarget().profile.userId==10&&retired&&profileLaunchAttempted&&bootstrapDispatched&&displayId>1
            &&brokerExitObserved&&Integer.valueOf(0).equals(brokerExitCode)&&"CLEANUP_UNKNOWN".equals(state);}
    /** Read-only absence recovery for a stopped personal Notes lease. The original
     * broker exit/release remains unknown; only a new opaque receipt can close it.
     * A failed display create can precede bootstrap launch. Eligibility admits
     * the strict original-record check; it does not itself retire the lease. */
    synchronized boolean personalNotesRecoveryEligible(){return publicOwnGroupScope!=null&&profileTarget()==null
            &&requiresPersonalNotesRetirement()&&retired&&(bootstrapDispatched||spawnAttempted)&&displayId>1&&"CLEANUP_UNKNOWN".equals(state);}
    synchronized void acceptReconciliation(Cleanup result)throws Exception{
        if(result==null)throw new IOException("后台清理凭据缺失");
        if(result.businessRecovery!=null){
            PublicProfileBusinessRecoveryClient.Receipt receipt=result.businessRecovery;
            if(result.prelaunchRecovery!=null||result.postlaunchRecovery!=null||result.publicProfileRecovery!=null||result.personalNotesRecovery!=null
                    ||!result.known||!publicProfileRecoveryEligible()||hasUnreleased(context)||!displayAbsent(context,displayId,displayName)
                    ||!generation.equals(result.evidence.getString("generation"))||!receipt.request.source().equals(result.evidence.getString("reconciliation_source"))
                    ||!receipt.receiptSha256().equals(result.evidence.getString("business_receipt_sha256")))
                throw new IOException("业务恢复凭据不属于当前原始停止租约");
            receipt.requireLease(taskId,generation,ownerSha256,createdElapsed,expiresElapsed,bootCount,profileTarget(),publicOwnGroupScope,displayId);
            retirePublicScope();retired=true;state="RELEASED";cleanupConfirmed=true;return;
        }
        if(result.personalNotesRecovery!=null){
            PublicPersonalNotesRecoveryClient.Receipt receipt=result.personalNotesRecovery;
            if(result.prelaunchRecovery!=null||result.postlaunchRecovery!=null||result.publicProfileRecovery!=null
                    ||!result.known||!personalNotesRecoveryEligible()||hasUnreleased(context)
                    ||!displayAbsent(context,displayId,displayName)||!generation.equals(result.evidence.getString("generation"))
                    ||!receipt.request.source().equals(result.evidence.getString("reconciliation_source"))
                    ||!receipt.receiptSha256().equals(result.evidence.getString("personal_notes_receipt_sha256")))
                throw new IOException("备忘录缺席恢复凭据不属于当前停止的个人空间租约");
            receipt.requireLease(taskId,generation,ownerSha256,createdElapsed,expiresElapsed,bootCount,publicOwnGroupScope,displayId);
            retirePublicScope();retired=true;state="RELEASED";cleanupConfirmed=true;return;
        }
        if(result.publicProfileRecovery!=null){
            PublicProfileRecoveryClient.Receipt receipt=result.publicProfileRecovery;
            if(result.prelaunchRecovery!=null||result.postlaunchRecovery!=null||!result.known||!publicProfileRecoveryEligible()
                    ||hasUnreleased(context)||!displayAbsent(context,displayId,displayName)
                    ||!generation.equals(result.evidence.getString("generation"))
                    ||receipt.request.postlaunch!=(displayId>1)||receipt.request.displayId!=displayId
                    ||!receipt.request.source().equals(result.evidence.getString("reconciliation_source"))
                    ||!receipt.receiptSha256().equals(result.evidence.getString("public_profile_receipt_sha256")))
                throw new IOException("公共恢复凭据不属于当前已停止的租约");
            receipt.requireLease(taskId,generation,ownerSha256,createdElapsed,expiresElapsed,bootCount,profileTarget(),publicOwnGroupScope,displayId);
            retirePublicScope();retired=true;state="RELEASED";cleanupConfirmed=true;return;
        }
        if(result.postlaunchRecovery!=null){
            ProfilePostlaunchRecoveryClient.Receipt receipt=result.postlaunchRecovery;
            if(result.prelaunchRecovery!=null||!result.known||!postlaunchRecoveryEligible()
                    ||hasUnreleased(context)||!displayAbsent(context,displayId,displayName)
                    ||!generation.equals(result.evidence.getString("generation"))
                    ||!ProfilePostlaunchRecovery.SOURCE.equals(result.evidence.getString("reconciliation_source"))
                    ||!receipt.receiptSha256().equals(result.evidence.getString("postlaunch_receipt_sha256")))
                throw new IOException("已启动恢复凭据不属于当前租约");
            receipt.requireLease(taskId,generation,ownerSha256,createdElapsed,expiresElapsed,bootCount,profileTarget(),displayId);
            retired=true;state="RELEASED";cleanupConfirmed=true;return;
        }
        if(result.prelaunchRecovery==null){acceptReconciliation(result.evidence);return;}
        ProfileRecoveryClient.Receipt receipt=result.prelaunchRecovery;
        if(!result.known||publicOwnGroupScope!=null||profileTarget()==null||profileLaunchAttempted||displayId!=-1
                ||hasUnreleased(context)||!displayAbsent(context,displayId,displayName)
                ||!generation.equals(result.evidence.getString("generation"))
                ||!ProfilePrelaunchRecovery.SOURCE.equals(result.evidence.getString("reconciliation_source"))
                ||!receipt.receiptSha256().equals(result.evidence.getString("prelaunch_receipt_sha256")))
            throw new IOException("启动前恢复凭据不属于当前租约");
        // The opaque receipt came from a newly owned read-only process; re-read its durable private bytes.
        // This never synthesizes the original broker's close/RELEASED response.
        receipt.requireLease(taskId,generation,ownerSha256,createdElapsed,expiresElapsed,bootCount,profileTarget());
        retired=true;state="RELEASED";cleanupConfirmed=true;
    }
    synchronized void acceptReconciliation(JSONObject proof)throws Exception{
        if(!proof.getBoolean("cleanup_known")||!generation.equals(proof.optString("generation"))
                ||hasUnreleased(context)||!displayAbsent(context,displayId,displayName))
            throw new IOException("后台清理凭据不属于当前租约");
        if(profileTarget()!=null){
            JSONObject response=proof.getJSONObject("broker_response");
            if(!Boolean.TRUE.equals(proof.get("broker_released"))||!Boolean.TRUE.equals(response.get("ok"))
                    ||!"RELEASED".equals(response.getString("state"))||!"close".equals(response.getString("operation"))
                    ||strictInt(response,"version")!=protocolVersion()
                    ||!generation.equals(response.getString("generation")))
                throw new IOException("profile reconciliation lacks the actual release response");
            ensureProfileCleanup(response);
        }
        if(publicOwnGroupScope!=null){
            JSONObject response=proof.getJSONObject("broker_response");
            if(!Boolean.TRUE.equals(proof.get("broker_released"))||!Boolean.TRUE.equals(response.get("ok"))
                    ||!"RELEASED".equals(response.getString("state"))||!"close".equals(response.getString("operation"))
                    ||strictInt(response,"version")!=protocolVersion()
                    ||!publicOwnGroupScope.sha256.equals(response.getString("display_scope_sha256")))
                throw new IOException("PUBLIC_SCOPE_RECONCILIATION_NOT_VERIFIED");
            retirePublicScope();
        }
        retired=true;state="RELEASED";cleanupConfirmed=true;
    }
    synchronized JSONObject evidence(){
        try{JSONObject value=baseJournal().put("retired",retired).put("spawn_attempted",spawnAttempted)
                .put("bootstrap_dispatched",bootstrapDispatched).put("bootstrap_model_issued",false)
                .put("broker_process_exit_observed",brokerExitObserved)
                .put("broker_process_exit_code",brokerExitCode==null?JSONObject.NULL:brokerExitCode)
                .put("broker_output",brokerOutput==null?JSONObject.NULL:brokerOutput.evidence())
                .put("app_display_readback",appDisplayReadback==null?JSONObject.NULL:new JSONObject(appDisplayReadback.toString()))
                .put("last_broker_response",lastResponse==null?JSONObject.NULL:new JSONObject(lastResponse.toString()));
            if(personalNotesCleanupEvidence!=null)value.put("personal_notes_cleanup",new JSONObject(personalNotesCleanupEvidence.toString()));
            CalendarDateRpcTrace calendarTrace=calendarDateRpcTrace;
            if(calendarTrace!=null)value.put("calendar_date_client_transport",calendarTrace.evidence());
            // Keep the exact existing Selection observation/wire schema. New
            // route audit belongs to this real session, never to screen data.
            if(selection.taskTarget!=null)value.put("execution_target",new JSONObject(selection.taskTarget.evidence()));
            return value;
        }
        catch(Exception failure){throw new IllegalStateException("后台会话凭据编码失败",failure);}
    }
    private JSONObject baseJournal()throws Exception{JSONObject value=new JSONObject().put("schema",SCHEMA).put("task_id",taskId)
            .put("app_uid",android.os.Process.myUid()).put("owner_sha256",ownerSha256)
            .put("generation",generation).put("socket",socketName).put("display_name",displayName)
            .put("display_id",displayId).put("state",state).put("created_elapsed_ms",createdElapsed).put("expires_elapsed_ms",expiresElapsed)
            .put("boot_count",bootCount).put("selection",selection.json())
            // This durable pre-spawn ceiling covers every later permitted Xiaomi launch.
            .put("owned_task_retirement_required",publicOwnGroupScope!=null||profileTarget()!=null||selection.allowedPackages.contains("com.xiaomi.shop"));
        if(publicOwnGroupScope!=null)value.put("public_own_group_scope_wire",publicOwnGroupScope.wire())
                .put("public_own_group_scope_sha256",publicOwnGroupScope.sha256).put("public_own_group_experimental",true)
                .put("public_scope_serialization_grants_authority",false);
        if(requiresPersonalNotesRetirement())value.put("personal_notes_retirement_required",true);
        if(profileTarget()!=null)value.put("profile_target_wire",profileTarget().wire()).put("profile_target_sha256",profileTarget().sha256)
                .put("profile_isolation_required",true).put("profile_launch_attempted",profileLaunchAttempted);
        if(profileCleanupEvidence!=null)value.put("profile_cleanup",new JSONObject(profileCleanupEvidence.toString()));
        return value;
    }

    /** Worker only. The durable lease precedes su and the first create request. */
    void start(HeptaAccessibilityService.Cancellation cancellation)throws Exception{
        startInternal(cancellation,null,Long.MAX_VALUE);
    }
    void startWithPermissionInitialization(HeptaAccessibilityService.Cancellation cancellation,InitializationHandler handler,long originalDeadline)throws Exception{
        if(handler==null||profileTarget()==null||!ProfileTarget.CTRIP.equals(profileTarget().packageName))
            throw new IllegalArgumentException("隔离用户携程初始化绑定缺失");
        startInternal(cancellation,handler,originalDeadline);
    }
    private void startInternal(HeptaAccessibilityService.Cancellation cancellation,InitializationHandler handler,long originalDeadline)throws Exception{
        LocalProbeApplication.requirePermissionPreparationIdle(context);
        if(android.os.Looper.myLooper()==android.os.Looper.getMainLooper())throw new IllegalStateException("后台创建不得阻塞主线程");
        if(publicOwnGroupScope==null)requireUnlocked();else requireNoPositiveAppCredential();
        filesRoot.unchanged(context);
        if(profileTarget()!=null)ProfileCatalogueClient.requireCurrent(context,profileTarget());
        MobiMindPrivateFiles.writeNew(journal,baseJournal().toString().getBytes(StandardCharsets.UTF_8));
        if(cancellation.isCancelled())throw new IllegalStateException("任务已停止，后台空间未启动");
        File apk=new File(context.getApplicationInfo().sourceDir).getCanonicalFile();
        if(!apk.isFile()||!apk.isAbsolute())throw new IOException("已安装 APK 路径不可用");
        String packages=join(selection.allowedPackages);
        String command="CLASSPATH="+quote(apk.getPath())+" /system/bin/app_process / "+BROKER
                +" --socket "+quote(socketName)+" --owner-uid "+android.os.Process.myUid()
                +" --generation "+quote(generation)+" --allowed-packages "+quote(packages)
                +(profileTarget()==null?"":" --profile-target "+quote(profileTarget().wire()))
                +(publicOwnGroupScope==null?"":" --public-own-group-scope "+quote(publicOwnGroupScope.wire()))
                +" --ttl-ms "+TTL_MS+" --expires-elapsed-ms "+expiresElapsed;
        File taskRoot=MobiMindPrivateFiles.directory(new File(filesRoot.path,"control-tasks"),false);
        File taskDirectory=MobiMindPrivateFiles.directory(new File(taskRoot,taskId),false);
        LocalProbeApplication.requirePermissionPreparationIdle(context);
        brokerProcess=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        spawnAttempted=true;
        brokerOutput=new BrokerOutput(brokerProcess,taskDirectory,taskId,generation,command);
        brokerOutputThread=new Thread(brokerOutput,"hepta-background-broker-output");
        brokerOutputThread.setDaemon(true);brokerOutputThread.start();
        long connectDeadline=Math.min(expiresElapsed,SystemClock.elapsedRealtime()+4500);
        Exception connectionFailure=null;
        while(SystemClock.elapsedRealtime()<connectDeadline){
            if(cancellation.isCancelled())throw new IllegalStateException("任务已停止，正在释放后台空间");
            try{JSONObject response=call("create",null,3000);accept(response,true);connectionFailure=null;break;}
            catch(ConnectionUnavailable error){connectionFailure=error;SystemClock.sleep(80);}
        }
        if(connectionFailure!=null||!"ACTIVE".equals(state))throw new IOException("手机后台执行服务未就绪；请确认本机已允许 Hepta 的 su 请求",connectionFailure);
        requireActive();saveJournal();
        if(cancellation.isCancelled())throw new IllegalStateException("任务已停止，正在释放后台空间");
        if(profileTarget()!=null){profileLaunchAttempted=true;saveJournal();}
        JSONObject launch;
        if(handler==null)launch=call("launch",selection.initialPackage,4000);
        else{
            if(cancellation.isCancelled())throw new IOException("权限初始化任务已停止");
            long deadline=Math.min(expiresElapsed,boundedActionDeadline(originalDeadline,9000));
            JSONObject request=request("prepare",selection.initialPackage,deadline);
            if(publicOwnGroupScope!=null&&selection.controllerUi!=null)
                request.put("controller_ui_locator",selection.controllerUi.wire());
            launch=exchangeForSession(request,9500,cancellation);
        }
        bootstrapDispatched=launch.optBoolean("dispatched",false);
        accept(launch,true);requireActive();saveJournal();
        if(handler!=null){
            requireControllerUiObservation(launch);
            if(!launch.getBoolean("profile_permission_preparing"))throw new IOException("后台未进入权限初始化阶段");
            permissionPreparing=true;handler.prepare(this,Math.min(originalDeadline,expiresElapsed),cancellation);
            requirePermissionPreparationActive();
            if(!"APP_READY".equals(readPreparation(cancellation,originalDeadline)))throw new IOException("权限初始化后未读回普通应用窗口");
            finishPermissionPreparation(cancellation,originalDeadline);saveJournal();
        }
    }
    private void requireControllerUiObservation(JSONObject response)throws Exception{
        if(publicOwnGroupScope==null||selection.controllerUi==null)return;
        org.trillionnium.hepta.background.PublicPermissionControllerUi.Locator source=selection.controllerUi;
        JSONObject proof=response.getJSONObject("permission_controller_ui");
        requireProfileFields(proof,"schema","generation","scope_sha256","locator_sha256","owner_uid","owner_pid",
                "task_id","display_id","owned_display_id","component","actual_task_token_retained","observed_elapsed_ms",
                "serialized_locator_grants_authority","physical_input_authorized","observation_valid");
        if(!"hepta.permission-controller-ui-observation.v1".equals(proof.getString("schema"))
                ||!generation.equals(proof.getString("generation"))||!publicOwnGroupScope.sha256.equals(proof.getString("scope_sha256"))
                ||!HeptaAccessibilityService.sha(source.wire().getBytes(StandardCharsets.UTF_8)).equals(proof.getString("locator_sha256"))||strictInt(proof,"owner_uid")!=source.uid
                ||strictInt(proof,"owner_pid")!=source.pid||strictInt(proof,"task_id")!=source.task
                ||strictInt(proof,"display_id")!=source.display||strictInt(proof,"owned_display_id")!=displayId
                ||!org.trillionnium.hepta.background.PublicPermissionControllerUi.COMPONENT.equals(proof.getString("component"))
                ||!Boolean.TRUE.equals(proof.get("actual_task_token_retained"))
                ||!Boolean.TRUE.equals(proof.get("observation_valid"))
                ||!Boolean.FALSE.equals(proof.get("serialized_locator_grants_authority"))
                ||!Boolean.FALSE.equals(proof.get("physical_input_authorized"))
                ||strictLong(proof,"observed_elapsed_ms")<createdElapsed||strictLong(proof,"observed_elapsed_ms")>SystemClock.elapsedRealtime())
            throw new IOException("CONTROLLER_UI_OBSERVATION_UNBOUND");
    }
    /** No model-issued action can change the immutable package/display binding. */
    JSONObject action(String operation,String pkg,HeptaAccessibilityService.Cancellation cancellation)throws Exception{
        return action(operation,pkg,cancellation,Long.MAX_VALUE);
    }
    JSONObject action(String operation,String pkg,HeptaAccessibilityService.Cancellation cancellation,long actionDeadline)throws Exception{
        if(!"launch".equals(operation)&&!"back".equals(operation))throw new IllegalArgumentException("后台工具未授权");
        requireActive();if(cancellation.isCancelled())throw new IllegalStateException("任务已停止");
        if(pkg!=null&&!allows(pkg))throw new IllegalArgumentException("目标应用未在本次后台范围内");
        long deadline=boundedActionDeadline(actionDeadline,4000);
        JSONObject request=request(operation,pkg,deadline);
        JSONObject response=exchangeForSession(request,4500,cancellation);accept(response,true);requireActive();return response;
    }
    JSONObject fixedIntent(org.trillionnium.hepta.background.FixedIntentTarget target,String payload,String attemptId,HeptaAccessibilityService.Cancellation cancellation)throws Exception{
        return fixedIntent(target,payload,attemptId,cancellation,Long.MAX_VALUE);
    }
    JSONObject fixedIntent(org.trillionnium.hepta.background.FixedIntentTarget target,String payload,String attemptId,HeptaAccessibilityService.Cancellation cancellation,long actionDeadline)throws Exception{
        if(profileTarget()!=null)throw new IllegalStateException("profile mode does not grant fixed-intent tools");
        if(target==null||!org.trillionnium.hepta.background.FixedIntentTools.isTool(target.action))throw new IllegalArgumentException("fixed background tool required");
        org.trillionnium.hepta.background.FixedIntentTools.forAction(target.action).validatePayload(payload);
        if(attemptId==null||!attemptId.matches("[0-9a-f]{64}"))throw new IllegalArgumentException("durable attempt binding required");
        requireActive();if(cancellation.isCancelled())throw new IllegalStateException("任务已停止");
        if(!allows(target.packageName))throw new IllegalArgumentException("固定工具目标不在后台范围");
        long deadline=boundedActionDeadline(actionDeadline,4000);
        JSONObject request=request(target.action,target.packageName,deadline)
                .put("target_uid",target.uid).put("payload",payload).put("attempt_id",attemptId);
        JSONObject response=exchangeForSession(request,4500,cancellation);
        accept(response,true);requireActive();
        if(!target.action.equals(response.getString("operation"))||!response.getBoolean("dispatched"))throw new IOException("固定工具回执未确认派发");
        JSONObject proof=response.getJSONObject("fixed_intent"),installed=proof.getJSONObject("target");
        if(!"hepta.background-fixed-intent.v1".equals(proof.getString("schema"))||!request.getString("request_id").equals(proof.getString("request_id"))
                ||!generation.equals(proof.getString("generation"))||displayId()!=strictInt(proof,"display_id")
                ||!target.action.equals(proof.getString("action"))||!attemptId.equals(proof.getString("attempt_id"))
                ||!org.trillionnium.hepta.background.FixedIntentTarget.payloadSha256(payload).equals(proof.getString("payload_sha256"))
                ||strictInt(installed,"target_uid")!=target.uid||!target.packageName.equals(installed.getString("package"))
                ||!(target.packageName+"/"+target.className).equals(installed.getString("component"))
                ||!target.action.equals(installed.getString("action"))||!target.appLabel.equals(installed.getString("app_label"))
                ||!(target.permission==null?JSONObject.NULL.equals(installed.get("required_permission")):target.permission.equals(installed.get("required_permission")))
                ||!installed.getBoolean("exported")||!installed.getBoolean("activity_enabled")||!installed.getBoolean("application_enabled")
                ||!installed.getBoolean("declared_intent_filter_matched")||!installed.getBoolean("ordinary_caller_permission_checked")
                ||strictInt(proof,"ordinary_caller_uid")!=android.os.Process.myUid()||!proof.getBoolean("attempt_consumed"))
            throw new IOException("固定工具回执与本次动作/目标不匹配");
        String mime=org.trillionnium.hepta.background.FixedIntentTools.forAction(target.action).mimeType;
        if(!(mime==null?JSONObject.NULL.equals(proof.get("resolved_type")):mime.equals(proof.get("resolved_type"))))
            throw new IOException("固定工具回执 MIME 不匹配");
        return response;
    }
    void verifyRemote()throws Exception{requireActive();accept(call(publicOwnGroupScope!=null&&permissionPreparing?"prepare_state":"state",null,1800),true);requireActive();}
    void requireActive(){
        if(publicOwnGroupScope==null){requireLegacyActive();return;}
        if(retired||!"ACTIVE".equals(state)||displayId<=Display.DEFAULT_DISPLAY)
            throw new IllegalStateException("后台空间已退休或未完成创建；不会使用主屏幕");
        if(SystemClock.elapsedRealtime()>=expiresElapsed)throw new IllegalStateException("后台会话已到期");
        if(publicOwnGroupScope==null)requireUnlocked();
        try{
            if(publicOwnGroupScope!=null){
                requireNoPositiveAppCredential();
                if(android.os.Looper.myLooper()!=android.os.Looper.getMainLooper()
                        &&publicScopeLease.refreshRequired(publicScopeOwner,SystemClock.elapsedRealtime()))
                    refreshPublicPolicy(null,expiresElapsed,false);
            }
            appDisplayReadback=readAppDisplay(lastResponse,displayId);
            if(retired||!"ACTIVE".equals(state))throw new IOException("PUBLIC_SCOPE_RETIRED_DURING_APP_READ");
        }catch(Exception failure){
            if(publicOwnGroupScope!=null)retirePublicScope();
            throw new IllegalStateException("后台屏幕策略读回不一致："+HeptaAccessibilityService.message(failure),failure);
        }
    }
    /** Original legacy lock and monitor boundaries are preserved exactly. */
    private synchronized void requireLegacyActive(){
        if(retired||!"ACTIVE".equals(state)||displayId<=Display.DEFAULT_DISPLAY)
            throw new IllegalStateException("后台空间已退休或未完成创建；不会使用主屏幕");
        if(SystemClock.elapsedRealtime()>=expiresElapsed)throw new IllegalStateException("后台会话已到期");
        requireUnlocked();
        try{appDisplayReadback=readAppDisplay(lastResponse,displayId);}
        catch(Exception failure){throw new IllegalStateException("后台屏幕策略读回不一致："+HeptaAccessibilityService.message(failure),failure);}
    }
    /** A main-thread watcher may schedule a worker from the same live object.
     * This check has no authority to read nodes, dispatch an input or renew proof. */
    void requireAdmissionActive(){
        if(publicOwnGroupScope==null){requireActive();return;}
        if(retired||!"ACTIVE".equals(state)||displayId<=1)throw new IllegalStateException("后台显示作用域未激活或已退休");
        try{publicScopeLease.requireAdmission(publicScopeOwner,SystemClock.elapsedRealtime());
            requireNoPositiveAppCredential();readPublicDisplay(displayId);
        }catch(Exception unavailable){retirePublicScope();throw new IllegalStateException("后台显示准入已失效",unavailable);}
    }
    /** Worker-only, forced actual root RPC immediately before an input enters.
     * The original action/permission deadline and cancellation are preserved. */
    void requirePolicyBeforeEffect(HeptaAccessibilityService.Cancellation cancel,long originalDeadline){
        if(publicOwnGroupScope==null)return;
        if(android.os.Looper.myLooper()==android.os.Looper.getMainLooper())throw new IllegalStateException("实验显示输入必须由已有worker派发");
        try{refreshPublicPolicy(cancel,originalDeadline,true);requireActive();}
        catch(Exception unavailable){retirePublicScope();throw new IllegalStateException("派发前后台显示策略不可验证",unavailable);}
    }
    private void refreshPublicPolicy(HeptaAccessibilityService.Cancellation cancellation,long originalDeadline,boolean force)throws Exception{
        synchronized(publicScopeIo){
            if(retired||!"ACTIVE".equals(state)||displayId<=1)throw new IOException("PUBLIC_SCOPE_RETIRED");
            if(!force&&!publicScopeLease.refreshRequired(publicScopeOwner,SystemClock.elapsedRealtime()))return;
            long deadline=Math.min(expiresElapsed,boundedActionDeadline(originalDeadline,1500));
            JSONObject request=request("display_policy",null,deadline);
            JSONObject response=exchangeForSession(request,1500,cancellation);accept(response,true);
        }
    }
    private void requireNoPositiveAppCredential(){
        KeyguardManager keyguard=(KeyguardManager)context.getSystemService(Context.KEYGUARD_SERVICE);
        if(keyguard==null||keyguard.isKeyguardSecure()||keyguard.isDeviceSecure()||keyguard.isDeviceLocked()
                ||readBootCount(context)!=bootCount)
            throw new IllegalStateException("实验显示仅允许当前无凭据设备及同一次启动");
        // Public false values are only a negative guard. Permission to create/use
        // the display comes solely from the actual root direct-Binder readback.
    }
    private void retirePublicScope(){
        retired=true;if(publicScopeLease!=null)publicScopeLease.retire(publicScopeOwner);
    }
    private PublicOwnGroupPolicy.AppDisplay readPublicDisplay(int id)throws Exception{
        long begin=SystemClock.elapsedRealtime();DisplayManager manager=(DisplayManager)context.getSystemService(Context.DISPLAY_SERVICE);
        Display display=manager==null?null:manager.getDisplay(id);
        if(display==null||display.getDisplayId()!=id||!displayName.equals(display.getName())||!display.isValid())
            throw new IOException("PUBLIC_SCOPE_APP_DISPLAY_UNAVAILABLE");
        return new PublicOwnGroupPolicy.AppDisplay(id,display.getName(),display.getFlags(),display.isValid(),begin,SystemClock.elapsedRealtime());
    }
    /** The ordinary app uses only public Display getters; hidden constants stay in the broker. */
    private JSONObject readAppDisplay(JSONObject response,int id)throws Exception{
        appDisplayReadback=null; // A failed current read must not retain a prior successful readback as current evidence.
        if(publicOwnGroupScope!=null){
            PublicOwnGroupPolicy.AppDisplay actual=readPublicDisplay(id);
            PublicOwnGroupPolicy.Readback proof=publicScopeLease.current(publicScopeOwner,SystemClock.elapsedRealtime(),actual);
            if(response==null||proof!=publicScopeReadback||!proof.requestId.equals(response.getString("request_id"))
                    ||!publicOwnGroupScope.sha256.equals(response.getString("display_scope_sha256")))
                throw new IOException("PUBLIC_SCOPE_NOT_CURRENT_AUTHENTICATED_RESPONSE");
            return new JSONObject().put("schema","hepta.public-own-group.app-readback.v1")
                    .put("source","ordinary_app_public_display_readback").put("task_id",taskId).put("generation",generation)
                    .put("app_uid",android.os.Process.myUid()).put("app_pid",android.os.Process.myPid()).put("boot_count",bootCount)
                    .put("display_id",actual.id).put("display_name",actual.name).put("flags",actual.flags).put("valid",true)
                    .put("scope_sha256",publicOwnGroupScope.sha256).put("broker_request_id",proof.requestId)
                    .put("broker_readback_sha256",proof.sha256).put("root_rpc_registered",true)
                    .put("observed_started_elapsed_ms",actual.begin).put("observed_ended_elapsed_ms",actual.end)
                    .put("serialization_grants_authority",false);
        }
        BrokerProtocol.DisplayPolicy policy=readBrokerPolicy(response,id);
        long started=SystemClock.elapsedRealtime();
        DisplayManager manager=(DisplayManager)context.getSystemService(Context.DISPLAY_SERVICE);
        Display display=manager==null?null:manager.getDisplay(id);
        if(display==null||display.getDisplayId()!=id||!displayName.equals(display.getName())||!display.isValid())
            throw new IOException("后台屏幕身份已变化；不会使用主屏幕");
        int actualFlags=display.getFlags();
        boolean matched=actualFlags==policy.flags&&(actualFlags&policy.requiredMask)==policy.requiredMask
                &&(actualFlags&policy.forbiddenMask)==0;
        JSONObject readback=new JSONObject().put("schema","hepta.background-app-display-readback.v1")
                .put("source","ordinary_app_public_display_readback").put("flags_source","android.view.Display.getFlags")
                .put("task_id",taskId).put("generation",generation).put("display_id",id).put("display_name",displayName)
                .put("app_uid",android.os.Process.myUid()).put("app_pid",android.os.Process.myPid()).put("boot_count",bootCount)
                .put("broker_request_id",response.getString("request_id")).put("flags",actualFlags).put("valid",true)
                .put("flags_match_broker",matched)
                .put("observed_started_elapsed_ms",started).put("observed_ended_elapsed_ms",SystemClock.elapsedRealtime());
        appDisplayReadback=readback; // Retain an actual mismatch for diagnosis; it cannot authorize an action.
        if(!matched)throw new IOException("应用与后台服务的屏幕 flags 读回不一致");
        return readback;
    }
    private BrokerProtocol.DisplayPolicy readBrokerPolicy(JSONObject response,int id)throws Exception{
        if(response==null||id<=0||!Boolean.TRUE.equals(response.get("ok"))||!"ACTIVE".equals(response.getString("state"))
                ||strictInt(response,"version")!=protocolVersion()||!isUuid(response.getString("request_id"))||!generation.equals(response.getString("generation"))
                ||!java.util.Arrays.asList("create","state","launch","back","window","notes.create","web.search",
                    "prepare","prepare_state","permission_window","prepare_done").contains(response.getString("operation"))
                ||strictLong(response,"expires_elapsed_ms")!=expiresElapsed
                ||id!=strictInt(response,"display_id")||!displayName.equals(response.getString("display_name")))
            throw new IOException("后台策略回执身份不匹配");
        JSONObject value=response.getJSONObject("display_policy_readback");
        if(!BrokerProtocol.DisplayPolicy.SCHEMA.equals(value.getString("schema"))
                ||!"broker_framework_readback".equals(value.getString("source"))
                ||!"android.view.Display".equals(value.getString("flag_namespace"))
                ||!"android.view.Display.getFlags".equals(value.getString("flags_source"))
                ||!"android.view.IWindowManager.getDisplayImePolicy".equals(value.getString("ime_source"))
                ||!"android.view.WindowManager.DISPLAY_IME_POLICY_HIDE".equals(value.getString("ime_hide_constant"))
                ||!generation.equals(value.getString("generation"))||id!=strictInt(value,"display_id")
                ||!displayName.equals(value.getString("display_name")))throw new IOException("后台策略读回来源或会话不匹配");
        long begin=strictLong(value,"observed_started_elapsed_ms"),end=strictLong(value,"observed_ended_elapsed_ms");
        if(begin<createdElapsed||end<begin||end>=expiresElapsed||end>SystemClock.elapsedRealtime())
            throw new IOException("后台策略读回时间越界");
        JSONObject constants=value.getJSONObject("flag_constants");
        if(constants.length()!=BrokerProtocol.DisplayPolicy.REQUIRED.size()+BrokerProtocol.DisplayPolicy.FORBIDDEN.size())
            throw new IOException("后台 Display 常量集合不完整");
        Map<String,Integer> mapped=new LinkedHashMap<String,Integer>();
        for(String name:BrokerProtocol.DisplayPolicy.REQUIRED)mapped.put(name,strictInt(constants,name));
        for(String name:BrokerProtocol.DisplayPolicy.FORBIDDEN)mapped.put(name,strictInt(constants,name));
        BrokerProtocol.DisplayPolicy checked=BrokerProtocol.DisplayPolicy.checked(strictInt(value,"flags"),mapped,
                strictInt(value,"ime_actual"),strictInt(value,"ime_hide_value"));
        if(checked.flags!=strictInt(response,"flags")||checked.requiredMask!=strictInt(value,"required_mask")
                ||checked.forbiddenMask!=strictInt(value,"forbidden_mask"))throw new IOException("后台策略掩码或 flags 不匹配");
        return checked;
    }
    private static long strictLong(JSONObject value,String key)throws Exception{
        Object number=value.get(key);
        if(!(number instanceof Integer)&&!(number instanceof Long))throw new IOException("后台策略数值类型错误："+key);
        return ((Number)number).longValue();
    }
    private static int strictInt(JSONObject value,String key)throws Exception{
        long number=strictLong(value,key);if(number<0||number>Integer.MAX_VALUE)throw new IOException("后台策略数值越界："+key);
        return (int)number;
    }
    private void requireUnlocked(){KeyguardManager keyguard=(KeyguardManager)context.getSystemService(Context.KEYGUARD_SERVICE);
        if(keyguard==null||keyguard.isKeyguardLocked())throw new IllegalStateException("手机已锁定或锁屏状态未知，后台任务停止");}
    private synchronized void accept(JSONObject response,boolean requireSuccess)throws Exception{
        String next=response.getString("state");int id=response.getInt("display_id");
        if(profileTarget()!=null){
            ProfileTarget actual=ProfileTarget.fromWire(response.getString("profile_target_wire"));
            if(!profileTarget().same(actual))throw new IOException("profile target readback changed");
            if("ACTIVE".equals(next)&&Boolean.TRUE.equals(response.get("ok"))
                    &&!Boolean.TRUE.equals(response.get("profile_current_identity_verified")))
                throw new IOException("profile live identity was not verified");
        }
        if(displayId>0&&id!=displayId)throw new IOException("后台屏幕标识发生变化");
        if("ACTIVE".equals(next)&&id<=0)throw new IOException("后台服务返回了主屏或无效屏幕");
        JSONObject readback="ACTIVE".equals(next)?readAppDisplay(response,id):null;
        state=next;if(id>0)displayId=id;lastResponse=new JSONObject(response.toString());
        if(readback!=null)appDisplayReadback=readback;
        if("RELEASED".equals(next)||"CLEANUP_UNKNOWN".equals(next)||"CLOSING".equals(next)){
            retired=true;if(publicOwnGroupScope!=null)retirePublicScope();
        }
        if(requireSuccess&&!response.getBoolean("ok"))throw new IOException("后台服务拒绝："+response.optString("error","operation_failed")
                +" "+response.optString("message",""));
    }
    private JSONObject call(String operation,String pkg,int budget)throws Exception{
        JSONObject request=request(operation,pkg,SystemClock.elapsedRealtime()+budget);
        return exchangeForSession(request,budget+500,null);
    }
    private JSONObject exchangeForSession(JSONObject request,int timeout,HeptaAccessibilityService.Cancellation cancel)throws Exception{
        if(publicOwnGroupScope==null)return exchange(socketName,generation,request,timeout,cancel);
        final boolean closing="close".equals(request.getString("op"));
        final HeptaAccessibilityService.Cancellation original=cancel;
        HeptaAccessibilityService.Cancellation bound=new HeptaAccessibilityService.Cancellation(){public boolean isCancelled(){
            return (!closing&&retired)||(original!=null&&original.isCancelled());
        }};
        try{
            RootRpcReply reply=exchangeWithPeer(socketName,generation,request,timeout,bound);
            JSONObject response=reply.response;
            if("ACTIVE".equals(response.getString("state"))&&Boolean.TRUE.equals(response.get("ok"))){
                if(closing||retired||strictLong(response,"expires_elapsed_ms")!=expiresElapsed
                        ||!Boolean.FALSE.equals(response.get("public_scope_admission_retired"))
                        ||!Boolean.FALSE.equals(response.get("public_scope_closing"))
                        ||!displayName.equals(response.getString("display_name")))throw new IOException("PUBLIC_SCOPE_RESPONSE_LEASE_INVALID");
                PublicOwnGroupPolicy.Readback proof=PublicOwnGroupPolicy.Readback.fromWire(response.getString("public_own_group_readback_wire"),publicOwnGroupScope);
                int id=strictInt(response,"display_id");
                if(proof.display.displayId!=id||proof.display.flags!=strictInt(response,"flags")||(displayId>0&&displayId!=id))
                    throw new IOException("PUBLIC_SCOPE_RESPONSE_DISPLAY_CHANGED");
                PublicOwnGroupPolicy.AppDisplay actual=readPublicDisplay(id);
                publicScopeLease.registerRootRpc(publicScopeOwner,proof,reply.peerUid,request.getString("request_id"),reply.began,
                        SystemClock.elapsedRealtime(),actual);
                publicScopeReadback=proof;
            }
            if(!closing&&!Boolean.TRUE.equals(response.get("ok")))retirePublicScope();
            return response;
        }catch(ConnectionUnavailable unavailable){
            // No socket connected and no request byte was sent. Only the original
            // bounded create/connect loop may retry this unambiguous condition.
            if(!"create".equals(request.getString("op"))||!"INITIAL".equals(state)||retired)retirePublicScope();
            throw unavailable;
        }catch(Exception failure){if(!closing)retirePublicScope();throw failure;}
    }
    private JSONObject exchangeCalendarForSession(JSONObject request,int timeout,HeptaAccessibilityService.Cancellation cancel,
            HeptaAccessibilityService.CalendarInputAttempt attempt,CalendarDateRpcTrace trace)throws Exception{
        if(publicOwnGroupScope==null||attempt==null||cancel==null||trace==null||!"calendar_date".equals(request.getString("op")))
            throw new IOException("CALENDAR_DATE_RPC_SCOPE");
        final boolean closing="close".equals(request.getString("op"));
        final HeptaAccessibilityService.Cancellation original=cancel;
        HeptaAccessibilityService.Cancellation bound=new HeptaAccessibilityService.Cancellation(){public boolean isCancelled(){
            return (!closing&&retired)||(original!=null&&original.isCancelled());
        }};
        try{
            RootRpcReply reply=exchangeCalendarWithPeer(socketName,generation,request,timeout,bound,this,attempt,original,trace);
            JSONObject response=reply.response;trace.response(response);
            if("ACTIVE".equals(response.getString("state"))&&Boolean.TRUE.equals(response.get("ok"))){
                if(closing||retired||strictLong(response,"expires_elapsed_ms")!=expiresElapsed
                        ||!Boolean.FALSE.equals(response.get("public_scope_admission_retired"))
                        ||!Boolean.FALSE.equals(response.get("public_scope_closing"))
                        ||!displayName.equals(response.getString("display_name")))throw new IOException("PUBLIC_SCOPE_RESPONSE_LEASE_INVALID");
                PublicOwnGroupPolicy.Readback proof=PublicOwnGroupPolicy.Readback.fromWire(response.getString("public_own_group_readback_wire"),publicOwnGroupScope);
                int id=strictInt(response,"display_id");
                if(proof.display.displayId!=id||proof.display.flags!=strictInt(response,"flags")||(displayId>0&&displayId!=id))
                    throw new IOException("PUBLIC_SCOPE_RESPONSE_DISPLAY_CHANGED");
                PublicOwnGroupPolicy.AppDisplay actual=readPublicDisplay(id);
                publicScopeLease.registerRootRpc(publicScopeOwner,proof,reply.peerUid,request.getString("request_id"),reply.began,
                        SystemClock.elapsedRealtime(),actual);
                publicScopeReadback=proof;
            }
            if(!closing&&!Boolean.TRUE.equals(response.get("ok")))retirePublicScope();
            return response;
        }catch(ConnectionUnavailable unavailable){
            // No socket connected and no request byte was sent. Only the original
            // bounded create/connect loop may retry this unambiguous condition.
            if(!"create".equals(request.getString("op"))||!"INITIAL".equals(state)||retired)retirePublicScope();
            throw unavailable;
        }catch(Exception failure){if(!closing)retirePublicScope();throw failure;}
    }

    private static RootRpcReply exchangeCalendarWithPeer(String name,String generation,JSONObject request,int timeout,
            HeptaAccessibilityService.Cancellation cancellation,BackgroundSession source,
            HeptaAccessibilityService.CalendarInputAttempt attempt,HeptaAccessibilityService.Cancellation original,
            CalendarDateRpcTrace trace)throws Exception{
        long began=SystemClock.elapsedRealtime();
        boolean publicScope=BrokerProtocol.isPublicOwnGroupVersion(request.getInt("version"));
        if(!publicScope||source==null||attempt==null||original==null||trace==null||!"calendar_date".equals(request.getString("op")))
            throw new IOException("CALENDAR_DATE_RPC_SCOPE");
        byte[] bytes=request.toString().getBytes(StandardCharsets.UTF_8);
        if(bytes.length<1||bytes.length>REQUEST_LIMIT)throw new IOException("后台请求长度越界");
        // This is after the real publicScopeIo wait and before any new connect.
        if(cancellation.isCancelled()||SystemClock.elapsedRealtime()>=request.getLong("deadline_elapsed_ms"))
            throw new IOException("CALENDAR_DATE_RETIRED_BEFORE_CONNECT");
        try(LocalSocket socket=new LocalSocket()){
            try{socket.connect(new LocalSocketAddress(name,LocalSocketAddress.Namespace.ABSTRACT));}
            catch(IOException unavailable){throw new ConnectionUnavailable(unavailable);}
            trace.mark("socket_connected");
            // Android creates the socket FD during connect; setSoTimeout before it throws.
            socket.setSoTimeout(remainingActionTimeout(request,timeout,cancellation));
            Credentials peer=socket.getPeerCredentials();
            if(peer==null||(publicScope?peer.getUid()!=0:(peer.getUid()!=0&&peer.getUid()!=2000)))
                throw new IOException(publicScope?"实验后台服务必须是真实root socket peer":"后台服务身份不是 shell/root");
            trace.mark("root_peer_verified");
            DataOutputStream output=new DataOutputStream(socket.getOutputStream());
            socket.setSoTimeout(remainingActionTimeout(request,timeout,cancellation));
            // connect/peer inspection can block. Recheck the original action authority before the first write.
            // Once any request byte is attempted, ambiguity is retained; there is no second send.
            if(cancellation!=null&&(cancellation.isCancelled()||SystemClock.elapsedRealtime()>=request.getLong("deadline_elapsed_ms")))
                throw new IllegalStateException("后台动作已停止、租约已退休或原始截止时间已到；未发送请求");
            // No nested BG/profile RPC is permitted from this actual final attempt check.
            attempt.requireBeforeSend(source,original);
            if(cancellation.isCancelled()||SystemClock.elapsedRealtime()>=request.getLong("deadline_elapsed_ms"))
                throw new IOException("CALENDAR_DATE_RETIRED_BEFORE_WRITE");
            trace.mark("request_write_attempted");
            output.writeInt(bytes.length);output.write(bytes);output.flush();trace.mark("request_write_completed");
            DataInputStream input=new DataInputStream(socket.getInputStream());byte[] header=new byte[4];
            readResponseBytes(socket,input,header,request,timeout,cancellation);int length=ByteBuffer.wrap(header).getInt();
            if(length<1||length>RESPONSE_LIMIT)throw new IOException("后台响应长度越界");
            byte[] payload=new byte[length];readResponseBytes(socket,input,payload,request,timeout,cancellation);
            trace.payload(payload); // Complete bytes were received even if UTF-8/JSON/identity checks below fail.
            String decoded=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(payload)).toString();
            JSONTokener parser=new JSONTokener(decoded);Object value=parser.nextValue();
            if(!(value instanceof JSONObject)||parser.nextClean()!=0)throw new IOException("后台响应不是单个 JSON 对象");
            JSONObject result=(JSONObject)value;
            if(result.getInt("version")!=request.getInt("version")||!request.getString("request_id").equals(result.getString("request_id"))
                    ||!generation.equals(result.getString("generation")))throw new IOException("后台响应请求/会话标识不匹配");
            if(BrokerProtocol.isProfileVersion(request.getInt("version"))
                    &&(!request.getString("op").equals(result.getString("operation"))
                       ||!request.getString("target_sha256").equals(ProfileTarget.fromWire(result.getString("profile_target_wire")).sha256)))
                throw new IOException("profile response scope or operation differs");
            if(publicScope&&(!request.getString("op").equals(result.getString("operation"))
                    ||!request.getString("display_scope_sha256").equals(result.getString("display_scope_sha256"))))
                throw new IOException("PUBLIC_SCOPE_RESPONSE_IDENTITY_CHANGED");
            String state=result.getString("state");
            if(!java.util.Arrays.asList("INITIAL","ACTIVE","CLOSING","RELEASED","CLEANUP_UNKNOWN").contains(state))throw new IOException("后台响应状态未知");
            result.getBoolean("ok");result.getInt("display_id");
            return new RootRpcReply(result,peer.getUid(),began);
        }
    }

    private static final class ConnectionUnavailable extends IOException {
        private static final long serialVersionUID=1L;
        ConnectionUnavailable(IOException cause){super("后台 socket 尚不可连接",cause);}
    }
    private static long boundedActionDeadline(long requested,int budget){
        long now=SystemClock.elapsedRealtime(),deadline=Math.min(requested,now+budget);
        if(deadline<=now)throw new IllegalStateException("后台动作原始截止时间已到，未发送请求");return deadline;
    }
    private static int remainingActionTimeout(JSONObject request,int maximum,
            HeptaAccessibilityService.Cancellation cancellation)throws Exception{
        if(cancellation==null)return maximum;
        if(cancellation.isCancelled())throw new IOException("后台动作已停止或租约已退休；请求不重发");
        long remaining=request.getLong("deadline_elapsed_ms")-SystemClock.elapsedRealtime();
        if(remaining<=0)throw new java.net.SocketTimeoutException("后台动作原始截止时间已到；请求不重发");
        return (int)Math.min((long)maximum,remaining);
    }
    private static void readResponseBytes(LocalSocket socket,DataInputStream input,byte[] bytes,
            JSONObject request,int maximum,HeptaAccessibilityService.Cancellation cancellation)throws Exception{
        if(cancellation==null){input.readFully(bytes);return;}
        int offset=0;
        while(offset<bytes.length){
            socket.setSoTimeout(remainingActionTimeout(request,maximum,cancellation));
            int count=input.read(bytes,offset,bytes.length-offset);
            if(count<0)throw new java.io.EOFException("后台响应提前结束");
            offset+=count;
        }
        // A late read return is not a new budget or a completed action at the original deadline.
        remainingActionTimeout(request,maximum,cancellation);
    }
    /** One bounded framed request, peer UID checked before any request bytes are sent. */
    private static JSONObject exchange(String name,String generation,JSONObject request,int timeout)throws Exception{
        return exchange(name,generation,request,timeout,null);
    }
    private static JSONObject exchange(String name,String generation,JSONObject request,int timeout,
            HeptaAccessibilityService.Cancellation cancellation)throws Exception{
        return exchangeWithPeer(name,generation,request,timeout,cancellation).response;
    }
    private static final class RootRpcReply {
        final JSONObject response;final int peerUid;final long began;
        private RootRpcReply(JSONObject response,int peerUid,long began){this.response=response;this.peerUid=peerUid;this.began=began;}
    }
    private static RootRpcReply exchangeWithPeer(String name,String generation,JSONObject request,int timeout,
            HeptaAccessibilityService.Cancellation cancellation)throws Exception{
        long began=SystemClock.elapsedRealtime();
        boolean publicScope=BrokerProtocol.isPublicOwnGroupVersion(request.getInt("version"));
        byte[] bytes=request.toString().getBytes(StandardCharsets.UTF_8);
        if(bytes.length<1||bytes.length>REQUEST_LIMIT)throw new IOException("后台请求长度越界");
        try(LocalSocket socket=new LocalSocket()){
            try{socket.connect(new LocalSocketAddress(name,LocalSocketAddress.Namespace.ABSTRACT));}
            catch(IOException unavailable){throw new ConnectionUnavailable(unavailable);}
            // Android creates the socket FD during connect; setSoTimeout before it throws.
            socket.setSoTimeout(remainingActionTimeout(request,timeout,cancellation));
            Credentials peer=socket.getPeerCredentials();
            if(peer==null||(publicScope?peer.getUid()!=0:(peer.getUid()!=0&&peer.getUid()!=2000)))
                throw new IOException(publicScope?"实验后台服务必须是真实root socket peer":"后台服务身份不是 shell/root");
            DataOutputStream output=new DataOutputStream(socket.getOutputStream());
            socket.setSoTimeout(remainingActionTimeout(request,timeout,cancellation));
            // connect/peer inspection can block. Recheck the original action authority before the first write.
            // Once any request byte is attempted, ambiguity is retained; there is no second send.
            if(cancellation!=null&&(cancellation.isCancelled()||SystemClock.elapsedRealtime()>=request.getLong("deadline_elapsed_ms")))
                throw new IllegalStateException("后台动作已停止、租约已退休或原始截止时间已到；未发送请求");
            output.writeInt(bytes.length);output.write(bytes);output.flush();
            DataInputStream input=new DataInputStream(socket.getInputStream());byte[] header=new byte[4];
            readResponseBytes(socket,input,header,request,timeout,cancellation);int length=ByteBuffer.wrap(header).getInt();
            if(length<1||length>RESPONSE_LIMIT)throw new IOException("后台响应长度越界");
            byte[] payload=new byte[length];readResponseBytes(socket,input,payload,request,timeout,cancellation);
            String decoded=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(payload)).toString();
            JSONTokener parser=new JSONTokener(decoded);Object value=parser.nextValue();
            if(!(value instanceof JSONObject)||parser.nextClean()!=0)throw new IOException("后台响应不是单个 JSON 对象");
            JSONObject result=(JSONObject)value;
            if(result.getInt("version")!=request.getInt("version")||!request.getString("request_id").equals(result.getString("request_id"))
                    ||!generation.equals(result.getString("generation")))throw new IOException("后台响应请求/会话标识不匹配");
            if(BrokerProtocol.isProfileVersion(request.getInt("version"))
                    &&(!request.getString("op").equals(result.getString("operation"))
                       ||!request.getString("target_sha256").equals(ProfileTarget.fromWire(result.getString("profile_target_wire")).sha256)))
                throw new IOException("profile response scope or operation differs");
            if(publicScope&&(!request.getString("op").equals(result.getString("operation"))
                    ||!request.getString("display_scope_sha256").equals(result.getString("display_scope_sha256"))))
                throw new IOException("PUBLIC_SCOPE_RESPONSE_IDENTITY_CHANGED");
            String state=result.getString("state");
            if(!java.util.Arrays.asList("INITIAL","ACTIVE","CLOSING","RELEASED","CLEANUP_UNKNOWN").contains(state))throw new IOException("后台响应状态未知");
            result.getBoolean("ok");result.getInt("display_id");
            return new RootRpcReply(result,peer.getUid(),began);
        }
    }
    private synchronized void saveJournal()throws Exception{
        filesRoot.unchanged(context);
        JSONObject old=readJournal(journal);
        if(!generation.equals(old.getString("generation")))throw new IOException("后台持久租约身份发生变化");
        File temporary=new File(filesRoot.path,JOURNAL+"."+UUID.randomUUID().toString()+".tmp");
        MobiMindPrivateFiles.writeNew(temporary,baseJournal().toString().getBytes(StandardCharsets.UTF_8));
        Os.rename(temporary.getPath(),journal.getPath());MobiMindPrivateFiles.syncDirectory(filesRoot.path);
    }
    /** Retire locally first; release proof requires broker readback and app-side display absence. */
    synchronized Cleanup close(){
        retired=true;if(publicOwnGroupScope!=null)retirePublicScope();
        boolean known=false;String error=null;
        try{
            if(!MobiMindPrivateFiles.exists(journal)){
                if(spawnAttempted)throw new IOException("后台持久租约消失，清理无法核验");
                state="RELEASED";known=true;
            }else if(!spawnAttempted){state="RELEASED";known=true;deleteJournal();}
            else if("RELEASED".equals(state)&&lastResponse!=null&&displayAbsent(context,displayId,displayName)){
                // A failed launch can already return system-confirmed RELEASED and exit the broker.
                ensureProfileCleanup(lastResponse);ensurePersonalNotesCleanup(lastResponse);known=true;deleteJournal();
            }
            else{
                JSONObject response=call("close",null,3500);accept(response,false);
                known=response.getBoolean("ok")&&"RELEASED".equals(state)&&displayAbsent(context,displayId,displayName);
                if(known){ensureProfileCleanup(response);ensurePersonalNotesCleanup(response);deleteJournal();}else saveJournal();
            }
        }catch(Exception failure){known=false;error=HeptaAccessibilityService.message(failure);state="CLEANUP_UNKNOWN";
            try{if(MobiMindPrivateFiles.exists(journal))saveJournal();}catch(Exception ignored){} }
        if(brokerProcess!=null){
            try{brokerExitObserved=brokerProcess.waitFor(700,TimeUnit.MILLISECONDS);if(brokerExitObserved)brokerExitCode=brokerProcess.exitValue();}
            catch(InterruptedException interrupted){Thread.currentThread().interrupt();}
            if(!known&&!brokerExitObserved&&profileTarget()==null&&!requiresPersonalNotesRetirement())brokerProcess.destroy(); // Never counts as release evidence.
        }
        if(brokerOutput!=null){
            try{if(brokerOutputThread!=null)brokerOutputThread.join(200);}
            catch(InterruptedException interrupted){Thread.currentThread().interrupt();}
            brokerOutput.persist("session_close_snapshot");
        }
        cleanupConfirmed=known;
        try{JSONObject record=evidence().put("cleanup_known",known).put("cleanup_error",error==null?JSONObject.NULL:error);
            if(profileCleanupEvidence!=null)record.put("profile_cleanup",new JSONObject(profileCleanupEvidence.toString()));
            return new Cleanup(known,record);}
        catch(Exception impossible){throw new IllegalStateException(impossible);}
    }
    private void ensureProfileCleanup(JSONObject response)throws Exception{
        if(profileTarget()==null)return;
        JSONObject proof=checkedProfileCleanup(response,profileTarget(),publicOwnGroupScope,generation,displayId,profileLaunchAttempted);
        if(!displayAbsent(context,displayId,displayName))throw new IOException("profile display absence is not established");
        proof.put("display_absence_observed",true);profileCleanupEvidence=proof;
    }
    private void ensurePersonalNotesCleanup(JSONObject response)throws Exception{
        if(!requiresPersonalNotesRetirement())return;
        JSONObject proof=checkedPersonalNotesCleanup(response,publicOwnGroupScope,generation,displayId);
        if(!displayAbsent(context,displayId,displayName))throw new IOException("NOTES_APP_DISPLAY_ABSENCE_UNPROVED");
        personalNotesCleanupEvidence=proof;
    }
    private static JSONObject checkedPersonalNotesCleanup(JSONObject response,PublicOwnGroupPolicy.Scope scope,
            String generation,int display)throws Exception{
        // Business refusal and terminal custody are separate facts. A failed
        // notes.create may already carry the authenticated broker's RELEASED
        // proof; all scope, double-absence and history checks remain required.
        if(response==null||scope==null||scope.targetUserId!=0||!(response.get("ok") instanceof Boolean)
                ||!"RELEASED".equals(response.getString("state"))||!scope.sha256.equals(response.getString("display_scope_sha256")))
            throw new IOException("NOTES_CLEANUP_ROOT_SCOPE_UNBOUND");
        JSONObject proof=response.getJSONObject("personal_notes_cleanup");
        boolean concurrent="hepta.public-personal-notes-cleanup.v2".equals(proof.getString("schema"));
        if((!concurrent&&!"hepta.public-personal-notes-cleanup.v1".equals(proof.getString("schema")))
                ||!generation.equals(proof.getString("generation"))||!scope.sha256.equals(proof.getString("scope_sha256"))
                ||!"com.motorola.stylus".equals(proof.getString("package"))
                ||strictInt(proof,"target_uid")<10000||strictInt(proof,"target_uid")>=90000
                ||!Boolean.TRUE.equals(proof.get("cleanup_known"))||!Boolean.FALSE.equals(proof.get("identity_unknown"))
                ||!Boolean.FALSE.equals(proof.get("custodian_retained"))||!Boolean.FALSE.equals(proof.get("arbitrary_task_removal_used"))
                ||!Boolean.FALSE.equals(proof.get("force_stop_used"))||!Boolean.FALSE.equals(proof.get("caller_flag_is_cleanup_proof")))
            throw new IOException("NOTES_CLEANUP_PROOF_INVALID");
        if(concurrent&&(!"nonphysical_and_unresolved_recents".equals(proof.getString("history_preservation_scope"))
                ||!"pre_release_to_absence".equals(proof.getString("history_preservation_interval"))
                ||!"initial_to_absence".equals(proof.getString("hidden_history_preservation_interval"))
                ||!Boolean.FALSE.equals(proof.get("physical_history_frozen"))
                ||!(proof.get("unrelated_physical_history_changes_observed") instanceof Boolean)
                ||!(proof.get("recents_presentation_changes_observed") instanceof Boolean)
                ||!(proof.get("prior_hidden_history_preserved") instanceof Boolean)))
            throw new IOException("NOTES_CLEANUP_HISTORY_SCOPE_INVALID");
        if(Boolean.TRUE.equals(proof.get("no_display_create_attempted"))){
            if(display!=-1||proof.getInt("display_id")!=-1||!Boolean.FALSE.equals(proof.get("create_attempted"))
                    ||!Boolean.FALSE.equals(proof.get("launch_dispatched"))||proof.getJSONArray("actual_observed_tasks").length()!=0)
                throw new IOException("NOTES_CLEANUP_NOT_CREATED_DISAGREES");
        }else{
            if(display<=1||strictInt(proof,"display_id")!=display||strictInt(proof,"absence_reads")<2)
                throw new IOException("NOTES_CLEANUP_DOUBLE_ABSENCE_REQUIRED");
            for(String key:new String[]{"create_attempted","pre_release_tasks_verified","release_api_entered","release_api_returned",
                    "display_absence_verified","live_tasks_absent","all_recents_sections_absent"})
                if(!Boolean.TRUE.equals(proof.get(key)))throw new IOException("NOTES_CLEANUP_ABSENCE_UNPROVED");
            if(concurrent){
                if(!Boolean.TRUE.equals(proof.get("nonphysical_history_preserved"))
                        ||!Boolean.TRUE.equals(proof.get("nonphysical_hidden_history_preserved")))
                    throw new IOException("NOTES_CLEANUP_PROTECTED_HISTORY_UNPROVED");
            }else if(!Boolean.TRUE.equals(proof.get("prior_hidden_history_preserved")))
                throw new IOException("NOTES_CLEANUP_ABSENCE_UNPROVED");
        }
        return new JSONObject(proof.toString());
    }
    private static JSONObject checkedProfileCleanup(JSONObject response,ProfileTarget target,PublicOwnGroupPolicy.Scope publicScope,
            String generation,int display,boolean launched)throws Exception{
        if(response==null||!Boolean.TRUE.equals(response.get("profile_cleanup_known"))
                ||!target.same(ProfileTarget.fromWire(response.getString("profile_target_wire"))))
            throw new IOException("profile cleanup missing actual broker scope");
        JSONObject proof=response.getJSONObject("profile_cleanup");
        if(publicScope==null)requireProfileFields(proof,"schema","generation","display_id","target_sha256","user_id","user_serial","full_uid",
                "cleanup_known","live_tasks_absent","recents_tasks_absent","foreign_tasks_present","identity_unknown","owned_tasks");
        else requireProfileFields(proof,"schema","generation","display_id","target_sha256","user_id","user_serial","full_uid",
                "cleanup_known","live_tasks_absent","recents_tasks_absent","foreign_tasks_present","identity_unknown","owned_tasks",
                "public_foreign_recent_history","recents_absence_scope");
        if(!"hepta.profile-task-cleanup.v1".equals(proof.getString("schema"))
                ||!generation.equals(proof.getString("generation"))||display!=strictInt(proof,"display_id")
                ||!target.sha256.equals(proof.getString("target_sha256"))||target.profile.userId!=strictInt(proof,"user_id")
                ||target.profile.serial!=strictLong(proof,"user_serial")||target.fullUid!=strictInt(proof,"full_uid"))
            throw new IOException("profile cleanup identity differs");
        for(String key:new String[]{"cleanup_known","live_tasks_absent","recents_tasks_absent"})
            if(!Boolean.TRUE.equals(proof.get(key)))throw new IOException("profile cleanup absence unknown");
        for(String key:new String[]{"foreign_tasks_present","identity_unknown"})
            if(!Boolean.FALSE.equals(proof.get(key)))throw new IOException("profile cleanup identity unknown");
        JSONArray tasks=proof.getJSONArray("owned_tasks");
        if(tasks.length()>32||(launched&&tasks.length()==0))throw new IOException("profile owned task cleanup incomplete");
        Set<Integer> ids=new java.util.HashSet<Integer>(),ownedIds=new java.util.HashSet<Integer>();Set<String> tokens=new java.util.HashSet<String>();
        for(int i=0;i<tasks.length();i++){
            JSONObject task=tasks.getJSONObject(i);
            requireProfileFields(task,"task_id","parent_task_id","task_token_id","user_id","user_serial","full_uid","live_absent","recents_absent");
            int id=strictInt(task,"task_id"),parent=strictInt(task,"parent_task_id");
            String token=task.getString("task_token_id");
            if(id<=0||parent<=0||id==parent||!ids.add(id)||!isUuid(token)||!tokens.add(token)
                    ||target.profile.userId!=strictInt(task,"user_id")||target.profile.serial!=strictLong(task,"user_serial")
                    ||target.fullUid!=strictInt(task,"full_uid")||!Boolean.TRUE.equals(task.get("live_absent"))
                    ||!Boolean.TRUE.equals(task.get("recents_absent")))throw new IOException("profile leaf cleanup differs");
            ownedIds.add(id);ownedIds.add(parent);
        }
        if(publicScope!=null)checkedPublicProfileHistory(response,proof,publicScope,target,generation,display,ownedIds);
        return new JSONObject(proof.toString());
    }
    /** Consume only the public broker's terminal custody projection. Serialized
     * task IDs do not become removal authority or an independent Binder census.
     * A refused business operation may still carry a confirmed RELEASED cleanup. */
    private static void checkedPublicProfileHistory(JSONObject response,JSONObject proof,PublicOwnGroupPolicy.Scope scope,
            ProfileTarget target,String generation,int display,Set<Integer> ownedIds)throws Exception{
        JSONObject history=proof.getJSONObject("public_foreign_recent_history");
        boolean concurrent="hepta.public-profile-history-custody.v2".equals(history.getString("schema"));
        String expectedScope=concurrent?"owned_target_only_with_unrelated_physical_history_audited":"owned_target_only_with_foreign_history_preserved";
        if(target.profile.userId!=10||target.profile.parentUserId!=0||!ProfileTarget.supportsPackage(target.packageName)
                ||scope.targetUserId!=target.profile.userId||!scope.targetSha256.equals(target.sha256)
                ||!scope.generation.equals(generation)||strictInt(response,"version")!=BrokerProtocol.PUBLIC_OWN_GROUP_PROFILE_VERSION
                ||!generation.equals(response.getString("generation"))||display!=strictInt(response,"display_id")
                ||!"RELEASED".equals(response.getString("state"))||!scope.sha256.equals(response.getString("display_scope_sha256"))
                ||!Boolean.TRUE.equals(response.get("public_scope_admission_retired"))
                ||!Boolean.TRUE.equals(response.get("public_scope_closing"))
                ||!Boolean.FALSE.equals(response.get("profile_custody_retained"))
                ||!expectedScope.equals(proof.getString("recents_absence_scope")))
            throw new IOException("public profile cleanup scope differs");
        if(concurrent)requireProfileFields(history,"schema","target_sha256","foreign_dormant_history_preserved","history_refusal_latched",
                "history_refusal_reason","baseline_elapsed_ms","current_elapsed_ms","baseline_raw_sha256","current_raw_sha256",
                "nonowned_history_sha256","baseline_task_ids","owned_task_ids","owned_target_absent","serialized_task_ids_grant_authority",
                "history_preservation_scope","physical_history_frozen","unrelated_physical_history_changes_observed",
                "protected_history_sha256","current_protected_history_sha256","nonphysical_history_preserved","recents_presentation_changes_observed");
        else requireProfileFields(history,"schema","target_sha256","foreign_dormant_history_preserved","history_refusal_latched",
                "history_refusal_reason","baseline_elapsed_ms","current_elapsed_ms","baseline_raw_sha256","current_raw_sha256",
                "nonowned_history_sha256","baseline_task_ids","owned_task_ids","owned_target_absent","serialized_task_ids_grant_authority");
        if((!concurrent&&!"hepta.public-profile-history-custody.v1".equals(history.getString("schema")))
                ||!target.sha256.equals(history.getString("target_sha256"))
                ||!Boolean.TRUE.equals(history.get(concurrent?"nonphysical_history_preserved":"foreign_dormant_history_preserved"))
                ||!Boolean.FALSE.equals(history.get("history_refusal_latched"))||history.get("history_refusal_reason")!=JSONObject.NULL
                ||!Boolean.TRUE.equals(history.get("owned_target_absent"))
                ||!Boolean.FALSE.equals(history.get("serialized_task_ids_grant_authority")))
            throw new IOException("public profile preserved history is unknown");
        if(concurrent&&(!"nonphysical_and_unresolved_recents".equals(history.getString("history_preservation_scope"))
                ||!Boolean.FALSE.equals(history.get("physical_history_frozen"))
                ||!(history.get("unrelated_physical_history_changes_observed") instanceof Boolean)
                ||!(history.get("recents_presentation_changes_observed") instanceof Boolean)
                ||!Boolean.valueOf(!history.getBoolean("unrelated_physical_history_changes_observed")&&!history.getBoolean("recents_presentation_changes_observed")).equals(history.get("foreign_dormant_history_preserved"))
                ||!history.getString("protected_history_sha256").matches("[0-9a-f]{64}")
                ||!history.getString("protected_history_sha256").equals(history.getString("current_protected_history_sha256"))))
            throw new IOException("public profile protected history scope differs");
        long before=strictLong(history,"baseline_elapsed_ms"),after=strictLong(history,"current_elapsed_ms");
        if(before<scope.createdElapsedMs||after<before||after>SystemClock.elapsedRealtime())
            throw new IOException("public profile history clock differs");
        for(String key:new String[]{"baseline_raw_sha256","current_raw_sha256","nonowned_history_sha256"})
            if(!history.getString(key).matches("[0-9a-f]{64}"))throw new IOException("public profile history digest differs");
        Set<Integer> baseline=checkedProfileTaskIds(history.getJSONArray("baseline_task_ids"));
        Set<Integer> retained=checkedProfileTaskIds(history.getJSONArray("owned_task_ids"));
        if(!retained.equals(ownedIds)||!Collections.disjoint(baseline,retained))
            throw new IOException("public profile history task binding differs");
    }
    private static Set<Integer> checkedProfileTaskIds(JSONArray values)throws Exception{
        Set<Integer> ids=new java.util.HashSet<Integer>();
        for(int i=0;i<values.length();i++){
            Object raw=values.get(i);
            if(!(raw instanceof Integer)&&!(raw instanceof Long))throw new IOException("public profile task id type differs");
            long id=((Number)raw).longValue();
            if(id<=0||id>Integer.MAX_VALUE||!ids.add((int)id))throw new IOException("public profile task id differs");
        }
        return ids;
    }
    private static void requireProfileFields(JSONObject value,String... names)throws Exception{
        Set<String> expected=new TreeSet<String>(java.util.Arrays.asList(names)),actual=new TreeSet<String>();
        java.util.Iterator<String> keys=value.keys();while(keys.hasNext())actual.add(keys.next());
        if(!actual.equals(expected))throw new IOException("profile evidence fields differ");
    }
    /** Diagnostic bytes only. A log, EOF, exit, or reported RELEASED never grants lease cleanup. */
    private static final class BrokerOutput implements Runnable {
        private static final int LIMIT=65536;
        private final Process process;
        private final File directory;
        private final String task,generation,commandSha,name;
        private final long started=SystemClock.elapsedRealtime();
        private final ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        private long count;
        private boolean eof,readFailed;
        private JSONObject captured;
        BrokerOutput(Process process,File directory,String task,String generation,String command){
            this.process=process;this.directory=directory;this.task=task;this.generation=generation;
            commandSha=HeptaAccessibilityService.sha(command.getBytes(StandardCharsets.UTF_8));
            name="background-broker-"+generation;
        }
        public void run(){
            try(InputStream input=process.getInputStream()){
                byte[] buffer=new byte[1024];int n;
                while((n=input.read(buffer))!=-1){synchronized(this){
                    count+=n;int keep=Math.min(n,LIMIT-bytes.size());
                    if(keep>0)bytes.write(buffer,0,keep);
                }}
                synchronized(this){eof=true;}
            }catch(IOException failure){synchronized(this){readFailed=true;}}
            finally{persist("stream_terminal");}
        }
        private JSONObject snapshot(byte[] kept)throws Exception{return new JSONObject()
                .put("schema","hepta.background-broker-output.v1").put("task_id",task).put("generation",generation)
                .put("app_uid",android.os.Process.myUid()).put("app_pid",android.os.Process.myPid())
                .put("process_binding","owned_java_process_merged_stream").put("process_reference",System.identityHashCode(process))
                .put("command_sha256",commandSha).put("started_elapsed_ms",started)
                .put("output_file",name+".bin").put("receipt_file",name+".json")
                .put("output_limit_bytes",LIMIT).put("observed_bytes",count).put("stored_bytes",kept.length)
                .put("stored_sha256",HeptaAccessibilityService.sha(kept)).put("overflow",count>LIMIT)
                .put("eof_seen",eof).put("read_failed",readFailed)
                .put("merged_stdout_stderr",true).put("model_input",false).put("release_evidence",false);}
        synchronized void persist(String reason){
            if(captured!=null)return;
            byte[] kept=bytes.toByteArray();JSONObject value;
            try{value=snapshot(kept).put("capture_reason",reason).put("persisted",false);}
            catch(Exception impossible){throw new IllegalStateException(impossible);}
            try{
                MobiMindPrivateFiles.directory(directory,false);
                MobiMindPrivateFiles.writeNew(new File(directory,name+".bin"),kept);
                value.put("persisted",true);
                MobiMindPrivateFiles.writeNew(new File(directory,name+".json"),value.toString().getBytes(StandardCharsets.UTF_8));
            }catch(Exception failure){
                try{value.put("persisted",false).put("persistence_error",failure.getClass().getSimpleName());}
                catch(Exception impossible){throw new IllegalStateException(impossible);}
            }
            captured=value;
        }
        synchronized JSONObject evidence()throws Exception{
            return captured==null?snapshot(bytes.toByteArray()).put("persisted",false):new JSONObject(captured.toString());
        }
    }
    private void deleteJournal()throws Exception{
        filesRoot.unchanged(context);JSONObject prior=readJournal(journal);
        if(!generation.equals(prior.getString("generation")))throw new IOException("后台租约已替换，不能删除");
        Os.remove(journal.getPath());MobiMindPrivateFiles.syncDirectory(filesRoot.path);
    }
    static boolean hasUnreleased(Context context){
        try{return MobiMindPrivateFiles.exists(new File(new QualificationScopeConfig.FilesRoot(context).path,JOURNAL));}
        catch(Exception unknown){return true;}
    }
    /** Distinct positive-step absence contract; the ordinary zero-step path below is unchanged. */
    static Cleanup reconcileBusiness(Context context,BusinessReconciliationCheck check)throws Exception{
        if(check==null)throw new IOException("业务恢复缺少真实任务与队列预约");
        QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);File path=new File(root.path,JOURNAL);
        MobiMindPrivateFiles.Read original=MobiMindPrivateFiles.read(path,16384,true);JSONObject old=parseJournal(original.bytes);
        String generation=old.getString("generation"),name=old.getString("display_name"),task=old.getString("task_id"),owner=old.getString("owner_sha256");
        int display=old.getInt("display_id"),boot=old.getInt("boot_count");long expiry=old.getLong("expires_elapsed_ms");
        ProfileTarget target=journalProfileTarget(old);PublicOwnGroupPolicy.Scope scope=journalPublicScope(old);
        if(!isUuid(generation)||!("hepta-bg-"+generation).equals(name)||!name.equals(old.getString("socket"))
                ||scope==null||target==null||target.profile.userId!=10||!ProfileTarget.supportsPackage(target.packageName)
                ||display<=1||!Boolean.TRUE.equals(old.get("profile_launch_attempted"))||!"CLEANUP_UNKNOWN".equals(old.getString("state"))
                ||readBootCount(context)!=boot||expiry>=Long.MAX_VALUE-2000||SystemClock.elapsedRealtime()<=expiry+2000)
            throw new IOException("业务恢复仅适用于同一启动内已到期的已支持公共资料租约");
        check.checkBusiness(task,owner);root.unchanged(context);original.unchangedPath();
        PublicProfileBusinessRecoveryClient.Receipt receipt=PublicProfileBusinessRecoveryClient.collect(context,original,check);
        receipt.persist();JSONObject evidence=receipt.evidence();
        check.checkBusiness(task,owner);root.unchanged(context);receipt.requireOriginals(true);original.unchangedPath();
        byte[] current=MobiMindPrivateFiles.read(path,16384,true).bytes;
        if(!java.util.Arrays.equals(original.bytes,current)||!receipt.request.journalSha256.equals(HeptaAccessibilityService.sha(current))
                ||receipt.request.displayId!=display||!displayAbsent(context,display,name))throw new IOException("业务恢复提交前原租约或实际显示发生变化");
        receipt.requireCurrentClock();check.checkBusiness(task,owner);root.unchanged(context);receipt.requireOriginals(true);original.unchangedPath();
        receipt.requireCurrentClock();
        // The serial owner and reservation still hold. This is the sole mutation:
        // retire the exact expired active lease, leaving task/result/latch bytes intact.
        Os.remove(path.getPath());MobiMindPrivateFiles.syncDirectory(root.path);
        if(MobiMindPrivateFiles.exists(path))throw new IOException("业务恢复租约退休未确认");
        return new Cleanup(true,evidence,receipt,true);
    }
    /** Recovery never restarts a task or creates a display. It can only close the recorded lease. */
    static Cleanup reconcile(Context context)throws Exception{return reconcile(context,null);}
    static Cleanup reconcile(Context context,ReconciliationCheck prelaunchCheck)throws Exception{
        QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);
        File path=new File(root.path,JOURNAL);
        if(!MobiMindPrivateFiles.exists(path))return new Cleanup(true,new JSONObject().put("cleanup_known",true).put("no_lease",true));
        MobiMindPrivateFiles.Read originalRead=MobiMindPrivateFiles.read(path,16384,true);
        byte[] originalJournal=originalRead.bytes;
        JSONObject old=parseJournal(originalJournal);String generation=old.getString("generation"),socket=old.getString("socket"),name=old.getString("display_name");
        if(!isUuid(generation)||!("hepta-bg-"+generation).equals(socket)||!socket.equals(name))throw new IOException("旧后台租约身份无效");
        int id=old.getInt("display_id");long expiry=old.getLong("expires_elapsed_ms");
        ProfileTarget target=journalProfileTarget(old);PublicOwnGroupPolicy.Scope publicScope=journalPublicScope(old);
        if(publicScope!=null&&target!=null&&target.profile.userId==10&&prelaunchCheck!=null
                &&(id==-1&&Boolean.FALSE.equals(old.get("profile_launch_attempted"))
                    ||id>1&&Boolean.TRUE.equals(old.get("profile_launch_attempted")))&&"CLEANUP_UNKNOWN".equals(old.getString("state"))
                &&readBootCount(context)==old.getInt("boot_count")&&expiry<Long.MAX_VALUE-2000
                &&SystemClock.elapsedRealtime()>expiry+2000){
            // The normal UI epoch, serial recovery writer and drained service exclude Start/close.
            // Do not send even an old-broker close command in this read-only recovery branch.
            prelaunchCheck.check();originalRead.unchangedPath();
            PublicProfileRecoveryClient.Receipt receipt=PublicProfileRecoveryClient.collect(context,originalRead,prelaunchCheck);
            receipt.persist(context);final JSONObject verifiedEvidence=receipt.evidence();
            prelaunchCheck.check();root.unchanged(context);receipt.requireOriginals(true);originalRead.unchangedPath();
            byte[] current=MobiMindPrivateFiles.read(path,16384,true).bytes;
            if(!java.util.Arrays.equals(originalJournal,current)||!receipt.request.journalSha256.equals(HeptaAccessibilityService.sha(current))
                    ||receipt.request.displayId!=id||!displayAbsent(context,id,name))throw new IOException("公共恢复期间原租约或显示状态发生变化");
            receipt.request.requireFence(SystemClock.elapsedRealtime(),readBootCount(context));
            prelaunchCheck.check();root.unchanged(context);originalRead.unchangedPath();
            // Commit only the background lease. All original failure files and independent leases remain.
            Os.remove(path.getPath());MobiMindPrivateFiles.syncDirectory(root.path);
            return new Cleanup(true,verifiedEvidence,null,null,receipt);
        }
        if(publicScope!=null&&target==null&&prelaunchCheck!=null&&id>1
                &&journalRequiresPersonalNotes(old,publicScope)&&"CLEANUP_UNKNOWN".equals(old.getString("state"))
                &&readBootCount(context)==old.getInt("boot_count")&&expiry<Long.MAX_VALUE-2000
                &&SystemClock.elapsedRealtime()>expiry+2000){
            // No close, display, task, package or process mutation enters this branch.
            prelaunchCheck.check();originalRead.unchangedPath();
            PublicPersonalNotesRecoveryClient.Receipt receipt=PublicPersonalNotesRecoveryClient.collect(context,originalRead,prelaunchCheck);
            receipt.persist(context);final JSONObject verifiedEvidence=receipt.evidence();
            prelaunchCheck.check();root.unchanged(context);receipt.requireOriginals(true);originalRead.unchangedPath();
            byte[] current=MobiMindPrivateFiles.read(path,16384,true).bytes;
            if(!java.util.Arrays.equals(originalJournal,current)||!receipt.request.journalSha256.equals(HeptaAccessibilityService.sha(current))
                    ||receipt.request.displayId!=id||!displayAbsent(context,id,name))
                throw new IOException("备忘录缺席恢复期间原租约或显示状态发生变化");
            receipt.request.requireFence(SystemClock.elapsedRealtime(),readBootCount(context));
            prelaunchCheck.check();root.unchanged(context);receipt.requireOriginals(true);originalRead.unchangedPath();
            // Only this CAS-bound active lease is retired. Its failed task, cleanup and
            // original control-session bytes have already been durably archived.
            Os.remove(path.getPath());MobiMindPrivateFiles.syncDirectory(root.path);
            return new Cleanup(true,verifiedEvidence,null,null,null,receipt);
        }
        int recoveryVersion=publicScope==null?(target==null?BrokerProtocol.VERSION:BrokerProtocol.PROFILE_VERSION)
                :(target==null?BrokerProtocol.PUBLIC_OWN_GROUP_VERSION:BrokerProtocol.PUBLIC_OWN_GROUP_PROFILE_VERSION);
        JSONObject closeRequest=new JSONObject().put("version",recoveryVersion)
                .put("request_id",UUID.randomUUID().toString()).put("generation",generation)
                .put("deadline_elapsed_ms",SystemClock.elapsedRealtime()+3500).put("op","close");
        if(target!=null)closeRequest.put("target_sha256",target.sha256);
        if(publicScope!=null)closeRequest.put("display_scope_sha256",publicScope.sha256);
        JSONObject response=null,profileCleanup=null;boolean released=false,connectionUnavailable=false;
        try{response=exchange(socket,generation,closeRequest,4000);
            released=response.getBoolean("ok")&&"RELEASED".equals(response.getString("state"));
            if(response.getInt("display_id")>0)id=response.getInt("display_id");
            if(released&&target!=null)profileCleanup=checkedProfileCleanup(response,target,publicScope,generation,id,old.getBoolean("profile_launch_attempted"));
            if(released&&journalRequiresPersonalNotes(old,publicScope))
                checkedPersonalNotesCleanup(response,publicScope,generation,id);
        }catch(ConnectionUnavailable absent){connectionUnavailable=true;/* No fallback for an invalid/authentication-failed response. */}
        int currentBoot=readBootCount(context),oldBoot=old.getInt("boot_count");
        boolean newBoot=currentBoot>=0&&oldBoot>=0&&currentBoot!=oldBoot;
        boolean noLateCreate=newBoot||SystemClock.elapsedRealtime()>expiry+2000;
        if(!released&&connectionUnavailable&&publicScope==null&&target!=null&&prelaunchCheck!=null&&noLateCreate
                &&id==-1&&Boolean.FALSE.equals(old.get("profile_launch_attempted"))){
            prelaunchCheck.check();
            ProfileRecoveryClient.Receipt receipt=ProfileRecoveryClient.collect(context,originalJournal,prelaunchCheck);
            // Preserve the exact old lease and the distinct proof before retiring only this journal.
            receipt.persist(context);
            final JSONObject verifiedEvidence=receipt.evidence(); // All receipt IO/validation precedes retirement.
            prelaunchCheck.check();root.unchanged(context);
            byte[] currentJournal=MobiMindPrivateFiles.read(path,16384,true).bytes;
            if(!java.util.Arrays.equals(originalJournal,currentJournal)
                    ||!receipt.request.journalSha256.equals(HeptaAccessibilityService.sha(currentJournal))
                    ||!generation.equals(parseJournal(currentJournal).getString("generation"))
                    ||!displayAbsent(context,-1,name))throw new IOException("恢复期间原租约或显示状态发生变化");
            receipt.request.requireFence(SystemClock.elapsedRealtime(),readBootCount(context));
            prelaunchCheck.check();root.unchanged(context);
            // No task result, cleanup report, or broker diagnostic is rewritten by recovery.
            Os.remove(path.getPath());MobiMindPrivateFiles.syncDirectory(root.path);
            return new Cleanup(true,verifiedEvidence,receipt);
        }
        if(!released&&connectionUnavailable&&publicScope==null&&target!=null&&prelaunchCheck!=null&&noLateCreate
                &&id>0&&Boolean.TRUE.equals(old.get("profile_launch_attempted"))
                &&"CLEANUP_UNKNOWN".equals(old.getString("state"))){
            prelaunchCheck.check();
            ProfilePostlaunchRecoveryClient.Receipt receipt=ProfilePostlaunchRecoveryClient.collect(context,originalJournal,prelaunchCheck);
            receipt.persist(context);
            final JSONObject verifiedEvidence=receipt.evidence();
            prelaunchCheck.check();root.unchanged(context);
            byte[] currentJournal=MobiMindPrivateFiles.read(path,16384,true).bytes;
            if(!java.util.Arrays.equals(originalJournal,currentJournal)
                    ||!receipt.request.journalSha256.equals(HeptaAccessibilityService.sha(currentJournal))
                    ||!generation.equals(parseJournal(currentJournal).getString("generation"))
                    ||!displayAbsent(context,id,name))throw new IOException("已启动恢复期间原租约或显示状态发生变化");
            receipt.request.requireFence(SystemClock.elapsedRealtime(),readBootCount(context));
            prelaunchCheck.check();root.unchanged(context);
            // A distinct postlaunch absence proof retires only this exact journal, never the old task result.
            Os.remove(path.getPath());MobiMindPrivateFiles.syncDirectory(root.path);
            return new Cleanup(true,verifiedEvidence,null,receipt);
        }
        boolean ownedTaskRetirement=ownedTaskRetirementRequired(old);
        boolean known=(released||(!ownedTaskRetirement&&noLateCreate))&&displayAbsent(context,id,name);
        JSONObject evidence=new JSONObject().put("schema","hepta.background-reconcile.v1").put("generation",generation)
                .put("cleanup_known",known).put("broker_released",released).put("boot_changed",newBoot)
                .put("owned_task_retirement_required",ownedTaskRetirement)
                .put("no_late_create",noLateCreate).put("display_absence_observed",displayAbsent(context,id,name))
                .put("automatic_resume",false).put("broker_response",response==null?JSONObject.NULL:response);
        if(known&&target!=null){if(profileCleanup==null)throw new IOException("profile cleanup proof missing");profileCleanup.put("display_absence_observed",true);evidence.put("profile_cleanup",profileCleanup);}
        if(known){root.unchanged(context);if(!generation.equals(readJournal(path).getString("generation")))throw new IOException("清理期间后台租约发生变化");
            Os.remove(path.getPath());MobiMindPrivateFiles.syncDirectory(root.path);}
        return new Cleanup(known,evidence);
    }
    /** Old journals retain their old contract; new owned-task leases never infer recents absence. */
    private static boolean ownedTaskRetirementRequired(JSONObject journal)throws Exception{
        if(journalProfileTarget(journal)!=null)return true;
        if(!journal.has("owned_task_retirement_required"))return false;
        Object required=journal.get("owned_task_retirement_required");
        if(!(required instanceof Boolean))throw new IOException("后台任务退休要求不是严格布尔值");
        return ((Boolean)required).booleanValue();
    }
    private static ProfileTarget journalProfileTarget(JSONObject journal)throws Exception{
        if(!journal.has("profile_target_wire")){
            JSONObject selection=journal.optJSONObject("selection");
            if(journal.has("profile_target_sha256")||journal.has("profile_isolation_required")||journal.has("profile_launch_attempted")
                    ||(selection!=null&&(selection.has("profile_target_wire")||selection.has("profile_target_sha256"))))
                throw new IOException("profile journal is incomplete");
            return null;
        }
        ProfileTarget target=ProfileTarget.fromWire(journal.getString("profile_target_wire"));
        if(!target.sha256.equals(journal.getString("profile_target_sha256"))
                ||!Boolean.TRUE.equals(journal.get("profile_isolation_required"))
                ||!Boolean.TRUE.equals(journal.get("owned_task_retirement_required"))
                ||!(journal.get("profile_launch_attempted") instanceof Boolean))throw new IOException("profile journal scope differs");
        JSONObject selection=journal.getJSONObject("selection");
        if(!target.wire().equals(selection.getString("profile_target_wire"))
                ||!target.sha256.equals(selection.getString("profile_target_sha256")))throw new IOException("profile journal Selection differs");
        return target;
    }
    private static PublicOwnGroupPolicy.Scope journalPublicScope(JSONObject journal)throws Exception{
        if(!journal.has("public_own_group_scope_wire")){
            if(journal.has("public_own_group_scope_sha256")||journal.has("public_own_group_experimental")
                    ||journal.has("public_scope_serialization_grants_authority"))throw new IOException("PUBLIC_SCOPE_JOURNAL_INCOMPLETE");
            return null;
        }
        PublicOwnGroupPolicy.Scope scope=PublicOwnGroupPolicy.Scope.fromWire(journal.getString("public_own_group_scope_wire"));
        scope.requireConfig(strictInt(journal,"app_uid"),journal.getString("generation"),strictLong(journal,"expires_elapsed_ms"),journalProfileTarget(journal));
        if(!scope.sha256.equals(journal.getString("public_own_group_scope_sha256"))
                ||!scope.taskId.equals(journal.getString("task_id"))||!scope.ownerSha256.equals(journal.getString("owner_sha256"))
                ||scope.createdElapsedMs!=strictLong(journal,"created_elapsed_ms")||scope.bootCount!=strictInt(journal,"boot_count")
                ||!Boolean.TRUE.equals(journal.get("public_own_group_experimental"))
                ||!Boolean.FALSE.equals(journal.get("public_scope_serialization_grants_authority"))
                ||!Boolean.TRUE.equals(journal.get("owned_task_retirement_required")))throw new IOException("PUBLIC_SCOPE_JOURNAL_BINDING_INVALID");
        return scope;
    }
    private static JSONObject readJournal(File file)throws Exception{
        return parseJournal(MobiMindPrivateFiles.read(file,16384,true).bytes);
    }
    private static boolean journalRequiresPersonalNotes(JSONObject journal,PublicOwnGroupPolicy.Scope scope)throws Exception{
        if(scope==null||scope.targetUserId!=0){
            if(journal.has("personal_notes_retirement_required"))throw new IOException("NOTES_JOURNAL_SCOPE_INVALID");
            return false;
        }
        JSONObject selection=journal.getJSONObject("selection");
        boolean expected="com.motorola.stylus".equals(selection.getString("bootstrap_package"));
        if(expected){
            JSONArray allowed=selection.getJSONArray("allowed_packages");
            if(allowed.length()!=1||!"com.motorola.stylus".equals(allowed.get(0))
                    ||!"public_own_group_personal_no_credentials_v1".equals(selection.getString("display_scope_mode"))
                    ||!Boolean.TRUE.equals(journal.get("personal_notes_retirement_required")))
                throw new IOException("NOTES_JOURNAL_TASK_BINDING_INVALID");
        }else if(journal.has("personal_notes_retirement_required"))throw new IOException("NOTES_JOURNAL_SCOPE_INVALID");
        return expected;
    }
    private static JSONObject parseJournal(byte[] bytes)throws Exception{
        JSONObject value=new JSONObject(new String(bytes,StandardCharsets.UTF_8));
        if(!SCHEMA.equals(value.getString("schema"))||value.getInt("app_uid")!=android.os.Process.myUid())throw new IOException("后台租约格式或应用 UID 不匹配");
        long created=value.getLong("created_elapsed_ms"),expiry=value.getLong("expires_elapsed_ms");
        if(created<0||expiry<=created||expiry-created!=TTL_MS)throw new IOException("后台租约截止时间无效");
        journalProfileTarget(value);PublicOwnGroupPolicy.Scope publicScope=journalPublicScope(value);
        journalRequiresPersonalNotes(value,publicScope);
        return value;
    }
    private static boolean displayAbsent(Context context,int id,String name){
        DisplayManager manager=(DisplayManager)context.getSystemService(Context.DISPLAY_SERVICE);
        if(manager==null)return false;
        Display[] displays=manager.getDisplays();if(displays==null)return false;
        if(id>0&&manager.getDisplay(id)!=null)return false;
        for(Display display:displays)if(display==null||name.equals(display.getName()))return false;
        return true;
    }
    private static int readBootCount(Context context){try{return Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT);}catch(Exception unknown){return -1;}}
    private static boolean isUuid(String value){return value!=null&&value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");}
    private static void checkPackage(String value){if(value==null||value.length()>255||!value.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")
                ||"org.trillionnium.hepta.local".equals(value)||"com.android.systemui".equals(value)||"com.android.shell".equals(value))throw new IllegalArgumentException("后台应用包名无效或不允许");}
    private static String join(List<String> values){StringBuilder out=new StringBuilder();for(String value:values){if(out.length()>0)out.append(',');out.append(value);}return out.toString();}
    private static String quote(String value){return "'"+value.replace("'","'\\''")+"'";}
}
