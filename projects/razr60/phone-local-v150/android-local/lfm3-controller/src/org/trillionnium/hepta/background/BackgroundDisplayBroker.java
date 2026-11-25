package org.trillionnium.hepta.background;

import android.app.ActivityOptions;
import android.app.KeyguardManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.graphics.PixelFormat;
import android.hardware.display.DisplayManager;
import android.hardware.display.VirtualDisplay;
import android.media.Image;
import android.media.ImageReader;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.os.SystemClock;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.InputDevice;
import android.view.InputEvent;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.WindowManager;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONObject;

/**
 * One bounded display session, started only through an already-authorized shell/root app_process.
 * Included in the ordinary APK's DEX, but never instantiated inside the inference process.
 * No UiAutomation, network, executable tool, policy grant, secure capture, or default-screen input.
 */
public final class BackgroundDisplayBroker {
    private static final long STARTUP_MS = 8000, SOCKET_MS = 3000, CLEANUP_MS = 1500;
    private final BrokerProtocol.Config config;
    private final BrokerProtocol.Receipts receipts = new BrokerProtocol.Receipts();
    // Published before the watchdog starts; cancellation addresses only this owned read-only child.
    private final ProfileRecoveryBootCount publicBootCount=new ProfileRecoveryBootCount(SystemClock::elapsedRealtime);
    private volatile String bootReadRetirementFailure;
    private final PublicPersonalNotesReader.FailureAudit publicNotesReadFailures=new PublicPersonalNotesReader.FailureAudit();
    private volatile Throwable publicNotesCleanupFailure;
    private final PublicPolicyFailureAudit publicPolicyFailures=new PublicPolicyFailureAudit();
    private final Object dispatchGate = new Object();
    private volatile WindowInfosCapture calendarWindowCapture;
    private volatile JSONObject calendarProbeEvidence;
    private volatile String calendarProbeRequest;
    // Dedicated date handler; this lease retains its one-use dispatch claim.
    private final AtomicBoolean calendarDateConsumed=new AtomicBoolean();
    private volatile JSONObject calendarDateEvidence;
    private volatile String calendarDateRequest;
    private final long started = SystemClock.elapsedRealtime();
    private final long expires;
    private final String displayName;
    private final AtomicBoolean closing = new AtomicBoolean();
    private final AtomicBoolean cleanupStarted = new AtomicBoolean();
    private final CountDownLatch cleanupDone = new CountDownLatch(1);
    private volatile String state = "INITIAL";
    private volatile String terminalReason = "";
    private volatile boolean serve = true;
    private volatile boolean frameworkReady;
    private volatile boolean createInFlight;
    private volatile boolean effectInFlight;
    private volatile long requestDeadline;
    private volatile long connectionDeadline;
    private volatile long lastUnlockedCheck;
    private volatile long cleanupAt;
    private final ProfileCleanupFailureAudit profileCleanupFailures=new ProfileCleanupFailureAudit();
    private volatile int displayId = -1;
    private volatile int displayFlags;
    private volatile JSONObject displayPolicyReadback;
    private volatile PublicOwnGroupFramework publicOwnGroupFramework;
    private volatile boolean publicOwnGroupDisplayReady;
    private volatile PublicOwnGroupPolicy.Readback publicOwnGroupLastReadback;
    private final PublicOwnGroupScreenLease publicScreenLease;
    private volatile PowerManager publicPowerManager;
    private Method newDisplayWakeLock;
    private final AtomicBoolean publicAdmissionRetired=new AtomicBoolean();
    private final PublicOwnGroupSurfaceRetirement publicSurfaceRetirement=new PublicOwnGroupSurfaceRetirement();
    // Only the object actually returned by this session's create API. Never reconstructed from an id or wire.
    private volatile VirtualDisplay publicCreateReturnedHandle;
    private volatile PublicOwnGroupTaskFence publicTaskFence;
    private volatile PublicPermissionControllerUi.Bound permissionControllerUi;
    private int activeRequestPeerPid=-1;
    private volatile PublicPersonalNotesCustody publicNotesCustody;
    private volatile PublicPersonalNotesReader publicNotesReader;
    private volatile DisplayGeometry displayGeometry;
    private volatile JSONObject displayGeometryReadback;
    private final java.util.Map<String,Integer> displayFlagConstants=new java.util.LinkedHashMap<String,Integer>();
    private volatile LocalSocket connection;
    // Only the authenticated, already admitted work-profile close RPC can own this peer.
    private volatile LocalSocket authenticatedProfileClosePeer;
    private volatile LocalServerSocket server;
    private volatile Context shell;
    private volatile DisplayManager displays;
    private volatile KeyguardManager keyguard;
    private volatile VirtualDisplay virtual;
    private volatile ImageReader surfaceReader;
    private volatile HandlerThread displayThread;
    private Object activityTasks, windowManager, inputManager;
    private Method allRootTasks, startActivityAsUser, setImePolicy, getImePolicy, injectInput, keyDisplayId;
    private int virtualFlags, requiredDisplayFlags, forbiddenDisplayFlags, imeHide;
    private final Set<String> launched = new HashSet<String>();
    private volatile BackgroundOwnedSingleTask ownedSingleTask;
    private volatile ProfilePackages profilePackages;
    private volatile ProfilePackages.Readback profileReadback;
    private volatile ProfileOwnedTask profileOwnedTask;
    private volatile boolean profilePreparing;
    private volatile String profilePreparationState="NOT_STARTED";
    private boolean profileConfirmationDeferred;
    private String profileConfirmationSample="NOT_READ";
    private volatile java.util.Map<Integer,String> permissionPhysicalBaseline;
    private volatile java.util.Map<Integer,String> permissionPhysicalAudit;
    private volatile PermissionWindowObservation.PublicInitialization permissionProjectionBaseline,permissionProjectionCurrent;
    private volatile PermissionWindowObservation permissionWindow;
    private volatile String permissionWindowRequest;
    private volatile ProfileTaskPlatform profilePlatform;
    private volatile PublicProfileRecentHistory.Baseline publicProfileHistory;
    private volatile BrokerProtocol.Request activeProfileRequest;
    private volatile WindowOwnership profileWindow;
    private volatile String profileWindowRequest;
    private volatile boolean profileRequestDispatched;
    private volatile java.util.Map<String,Object> profileCleanupReadback;
    private volatile java.util.Map<String,Object> profilePersonalAudit;
    private final ProfileDisplayCustody profileCustody=new ProfileDisplayCustody();
    private final AtomicBoolean retainedCleanupServerStarted=new AtomicBoolean();
    private final RetainedProfileCleanupAttempt retainedCleanupAttempt;
    private final Set<String> fixedToolsConsumed=new HashSet<String>();
    private final java.util.Map<String,JSONObject> fixedIntentProofs=new java.util.LinkedHashMap<String,JSONObject>();
    private final java.util.Map<String,JSONObject> taskLaunchPolicies=new java.util.LinkedHashMap<String,JSONObject>();

    private BackgroundDisplayBroker(BrokerProtocol.Config config) throws BrokerProtocol.Refusal {
        this.config = config;
        retainedCleanupAttempt=new RetainedProfileCleanupAttempt(config,SystemClock::elapsedRealtime);
        if (config.expiresElapsedMs <= started) throw new BrokerProtocol.Refusal("START_EXPIRED");
        if(config.publicOwnGroupScope!=null&&config.publicOwnGroupScope.createdElapsedMs>started)
            throw new BrokerProtocol.Refusal("PUBLIC_SCOPE_CREATED_IN_FUTURE");
        expires = Math.min(started + config.ttlMs, config.expiresElapsedMs);
        displayName = "hepta-bg-" + config.generation;
        try { publicScreenLease=config.publicOwnGroupScope==null?null:
                new PublicOwnGroupScreenLease(config.generation,expires,SystemClock::elapsedRealtime); }
        catch(IOException invalid){throw new BrokerProtocol.Refusal(invalid.getMessage());}
    }

    public static void main(String[] args) {
        BackgroundDisplayBroker broker = null;
        int exit = 0;
        try {
            int uid = android.os.Process.myUid();
            if (uid != 0 && uid != 2000) throw new BrokerProtocol.Refusal("BROKER_REQUIRES_EXISTING_SHELL_OR_ROOT");
            BrokerProtocol.Config config=BrokerProtocol.Config.parse(args);
            if(config.publicOwnGroupScope!=null&&uid!=0)throw new BrokerProtocol.Refusal("PUBLIC_SCOPE_ROOT_REQUIRED");
            broker = new BackgroundDisplayBroker(config);
            final BackgroundDisplayBroker owner = broker;
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                owner.beginCleanup("process_shutdown");
                owner.awaitCleanup(CLEANUP_MS);
                owner.holdProfileCustody();
                owner.holdPublicNotesCustody();
            }, "HeptaBackgroundShutdown"));
            broker.startWatchdog();
            broker.initializeFramework();
            broker.listen();
        } catch (Throwable error) {
            exit = 70;
            String code = code(error);
            try { System.err.println(new JSONObject().put("schema", "hepta.background-broker-terminal.v1")
                .put("error", code).put("state", broker == null ? "INITIAL" : broker.state)); }
            catch (Throwable ignored) { System.err.println("background_broker_failed"); }
        } finally {
            if (broker != null) {
                broker.serve = false;
                broker.closeSockets();
                broker.beginCleanup("process_finally");
                broker.awaitCleanup(CLEANUP_MS);
                broker.printTerminal();
                if (!"RELEASED".equals(broker.state)) exit = 70;
            }
        }
        // Binder threads must not retain an orphaned shell process after the session ends.
        // A profile custodian is deliberately retained when owned-task absence is unknown.
        // SIGKILL/OS death remains unprovable: Binder death can destroy the virtual display.
        if(broker!=null)broker.holdProfileCustody();
        if(broker!=null)broker.holdPublicNotesCustody();
        System.exit(exit);
    }

    private void initializeFramework() throws Exception {
        if (Looper.getMainLooper() == null) Looper.prepareMainLooper();
        Object activityThread = Class.forName("android.app.ActivityThread").getMethod("systemMain").invoke(null);
        Context system = (Context) activityThread.getClass().getMethod("getSystemContext").invoke(activityThread);
        shell = system.createPackageContext("com.android.shell", 0);
        displays = (DisplayManager) shell.getSystemService(Context.DISPLAY_SERVICE);
        keyguard = (KeyguardManager) shell.getSystemService(Context.KEYGUARD_SERVICE);
        if (displays == null || keyguard == null) throw new BrokerProtocol.Refusal("FRAMEWORK_SERVICE_MISSING");
        if(config.publicOwnGroupScope!=null)publicOwnGroupFramework=new PublicOwnGroupFramework(
                shell,displays,config.publicOwnGroupScope,publicBootCount,Math.min(expires,started+STARTUP_MS));
        if(config.publicOwnGroupScope!=null){
            publicPowerManager=(PowerManager)shell.getSystemService(Context.POWER_SERVICE);
            if(publicPowerManager==null)throw new BrokerProtocol.Refusal("PUBLIC_SCREEN_POWER_SERVICE_UNAVAILABLE");
            // The two-argument overload can address all display groups. There is no fallback.
            newDisplayWakeLock=PowerManager.class.getMethod("newWakeLock",int.class,String.class,int.class);
        }
        requireUnlocked();
        virtualFlags = fields(DisplayManager.class, "VIRTUAL_DISPLAY_FLAG_PUBLIC", "VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY",
            "VIRTUAL_DISPLAY_FLAG_SUPPORTS_TOUCH", "VIRTUAL_DISPLAY_FLAG_DESTROY_CONTENT_ON_REMOVAL",
            "VIRTUAL_DISPLAY_FLAG_TRUSTED", "VIRTUAL_DISPLAY_FLAG_OWN_FOCUS", "VIRTUAL_DISPLAY_FLAG_STEAL_TOP_FOCUS_DISABLED");
        if(config.publicOwnGroupScope!=null)virtualFlags=publicOwnGroupFramework.requestedFlags;
        requiredDisplayFlags = fields(Display.class, "FLAG_TRUSTED", "FLAG_OWN_FOCUS", "FLAG_STEAL_TOP_FOCUS_DISABLED");
        forbiddenDisplayFlags = fields(Display.class, "FLAG_SECURE", "FLAG_ALWAYS_UNLOCKED");
        for(String name:BrokerProtocol.DisplayPolicy.REQUIRED)displayFlagConstants.put(name,Display.class.getField(name).getInt(null));
        for(String name:BrokerProtocol.DisplayPolicy.FORBIDDEN)displayFlagConstants.put(name,Display.class.getField(name).getInt(null));
        imeHide = WindowManager.class.getField("DISPLAY_IME_POLICY_HIDE").getInt(null);
        activityTasks = Class.forName("android.app.ActivityTaskManager").getMethod("getService").invoke(null);
        Class<?> atm = Class.forName("android.app.IActivityTaskManager");
        allRootTasks = atm.getMethod("getAllRootTaskInfos");
        startActivityAsUser = atm.getMethod("startActivityAsUser",
            Class.forName("android.app.IApplicationThread"), String.class, String.class,
            Intent.class, String.class, IBinder.class, String.class, int.class, int.class,
            Class.forName("android.app.ProfilerInfo"), Bundle.class, int.class);
        windowManager = Class.forName("android.view.WindowManagerGlobal").getMethod("getWindowManagerService").invoke(null);
        Class<?> wm = Class.forName("android.view.IWindowManager");
        setImePolicy = wm.getMethod("setDisplayImePolicy", int.class, int.class);
        getImePolicy = wm.getMethod("getDisplayImePolicy", int.class);
        Class<?> im = Class.forName("android.hardware.input.InputManagerGlobal");
        inputManager = im.getMethod("getInstance").invoke(null);
        // UID-targeted injection additionally rejects a target-window switch between the guard and dispatch.
        injectInput = im.getMethod("injectInputEvent", InputEvent.class, int.class, int.class);
        keyDisplayId = KeyEvent.class.getMethod("setDisplayId", int.class);
        if (activityTasks == null || windowManager == null || inputManager == null)
            throw new BrokerProtocol.Refusal("FRAMEWORK_SERVICE_MISSING");
        if(config.profileTarget==null) snapshot(); // Existing user-0 policy is unchanged.
        else {
            profilePackages=new ProfilePackages(shell);
            profileReadback=profilePreflight(Math.min(expires,started+STARTUP_MS));
        }
        checkOwnerPackages();
        if(config.publicOwnGroupScope!=null&&config.profileTarget==null
                &&config.packages.size()==1&&config.packages.contains(PublicPersonalNotesCustody.PACKAGE)){
            android.content.pm.ApplicationInfo before=shell.getPackageManager().getApplicationInfo(PublicPersonalNotesCustody.PACKAGE,0);
            PublicOwnGroupPhysicalFence.RecentCensus recents=PublicOwnGroupPhysicalFence.inspectRecents(
                    BackgroundTaskOrganizer.profileRecents(()->Math.min(expires,started+STARTUP_MS)));
            ProfileTaskPolicy.Snapshot actual=BackgroundTaskOrganizer.profileSnapshot(activityTasks);
            android.content.pm.ApplicationInfo after=shell.getPackageManager().getApplicationInfo(PublicPersonalNotesCustody.PACKAGE,0);
            if(before==null||after==null||before.uid!=after.uid||!before.enabled||!after.enabled
                    ||before.sourceDir==null||!before.sourceDir.equals(after.sourceDir))throw new BrokerProtocol.Refusal("NOTES_INSTALLATION_CHANGED");
            publicNotesCustody=new PublicPersonalNotesCustody(config.generation,config.publicOwnGroupScope.sha256,before.uid,actual,recents);
        }
        if(config.publicOwnGroupScope!=null)publicTaskFence=new PublicOwnGroupTaskFence(
                BackgroundTaskOrganizer.profileSnapshot(activityTasks),config.publicOwnGroupScope.targetUserId,config.generation);
        requireUnlocked();
        frameworkReady = true;
        Thread locks = new Thread(() -> {
            while (serve && !closing.get()) {
                try { requireUnlocked(); Thread.sleep(100); }
                catch (Throwable error) {
                    // requireUnlocked may have entered just before the ordinary close retired
                    // the wake lock. Its late result cannot cut the close reader off mid-frame.
                    if(!profileCloseReplyPending(SystemClock.elapsedRealtime()))shutdown(code(error));
                    return;
                }
            }
        }, "HeptaBackgroundKeyguard");
        locks.setDaemon(true); locks.start();
    }

    private void checkOwnerPackages() throws Exception {
        PackageManager pm = shell.getPackageManager();
        String[] owners = pm.getPackagesForUid(config.ownerUid);
        if (owners == null || owners.length == 0) throw new BrokerProtocol.Refusal("OWNER_UID_UNRESOLVED");
        boolean heptaOwner = false;
        for (String owner : owners) if ("org.trillionnium.hepta.local".equals(owner)) heptaOwner = true;
        if (!heptaOwner) throw new BrokerProtocol.Refusal("OWNER_PACKAGE_MISMATCH");
        if(config.profileTarget!=null){
            if(profileReadback==null||!config.profileTarget.same(profileReadback.target))
                throw new BrokerProtocol.Refusal("PROFILE_INSTALLATION_IDENTITY_CHANGED");
            return; // Target PM identity was resolved in its actual user, not the controller's user.
        }
        for (String pkg : config.packages) {
            if ("org.trillionnium.hepta.local".equals(pkg) || "com.android.systemui".equals(pkg)
                || "com.android.shell".equals(pkg)) throw new BrokerProtocol.Refusal("BROKER_CONTROL_PACKAGE_FORBIDDEN");
            Intent intent = pm.getLaunchIntentForPackage(pkg);
            if (intent == null || intent.getComponent() == null || !pkg.equals(intent.getComponent().getPackageName()))
                throw new BrokerProtocol.Refusal("PACKAGE_NOT_LAUNCHABLE");
        }
    }

    private void listen() throws Exception {
        if (closing.get() || SystemClock.elapsedRealtime() >= expires)
            throw new BrokerProtocol.Refusal("START_EXPIRED");
        server = new LocalServerSocket(config.socketName);
        while (serve && !closing.get()) {
            LocalSocket accepted;
            try { accepted = server.accept(); }
            catch (IOException error) { if (closing.get() || !serve) break; throw error; }
            connection = accepted;
            connectionDeadline = SystemClock.elapsedRealtime() + SOCKET_MS;
            requestDeadline = 0;
            try {
                accepted.setSoTimeout((int) SOCKET_MS);
                // No request is parsed, response disclosed, or display action attempted for another UID.
                if (accepted.getPeerCredentials().getUid() != config.ownerUid) continue;
                BrokerProtocol.Request request = null;
                byte[] response;
                try {
                    request = BrokerProtocol.Request.parse(BrokerProtocol.readFrame(accepted.getInputStream()));
                    request.authenticate(config, accepted.getPeerCredentials().getUid());
                    activeRequestPeerPid=accepted.getPeerCredentials().getPid();
                    response = receipts.replay(request);
                    if (response == null) {
                        request.checkDeadline(SystemClock.elapsedRealtime(), expires);
                        requestDeadline = Math.min(request.deadline, expires);
                        connectionDeadline = requestDeadline;
                        if(config.publicOwnGroupScope!=null&&config.profileTarget!=null&&"close".equals(request.operation))
                            authenticatedProfileClosePeer=accepted;
                        response = perform(request);
                        receipts.remember(request, response);
                    }
                } catch (Throwable error) {
                    response = response(request, false, code(error), false);
                }
                if(config.publicOwnGroupScope!=null&&(closing.get()||publicAdmissionRetired.get())
                        &&request!=null&&!"close".equals(request.operation)){
                    // This is our own already serialized receipt, possibly for a real dispatched
                    // effect. Retiring admission must never rewrite that historical truth to false.
                    JSONObject retired=new JSONObject(new String(response,StandardCharsets.UTF_8));
                    String firstError=retired.optString("error","");
                    boolean keepCalendarFailure=("calendar_probe".equals(request.operation)||"calendar_date".equals(request.operation))
                            &&Boolean.FALSE.equals(retired.opt("ok"))&&!firstError.isEmpty();
                    retired.put("ok",false).put("error",keepCalendarFailure?firstError:"PUBLIC_SCOPE_RETIRED").put("state",state)
                        .put("public_scope_admission_retired",true).put("public_scope_closing",true)
                        .put("public_own_group_readback_wire",JSONObject.NULL).put("public_surface_detach",publicDetachEvidence());
                    if(keepCalendarFailure)retired.put("public_scope_retirement_error","PUBLIC_SCOPE_RETIRED");
                    response=retired.toString().getBytes(StandardCharsets.UTF_8);
                }
                BrokerProtocol.writeFrame(accepted.getOutputStream(), response);
                // Only perform(close) may set closing. A rejected close envelope cannot retire the session.
                // Its successfully authenticated response is flushed before the loop notices closing.
            } catch (IOException error) {
                // EOF or a lost response never replays an effect with a new request identity.
                if (requestDeadline != 0) shutdown("CLIENT_TRANSPORT_LOST");
            } finally {
                try { accepted.close(); } catch (IOException ignored) {}
                authenticatedProfileClosePeer=null;
                connection = null; requestDeadline = 0; connectionDeadline = 0;activeRequestPeerPid=-1;
            }
        }
    }

    private byte[] perform(BrokerProtocol.Request r) throws Exception {
        boolean dispatched = false;
        if(config.profileTarget!=null){activeProfileRequest=r;profileWindow=null;profileWindowRequest=null;
            permissionWindow=null;permissionWindowRequest=null;profileRequestDispatched=false;}
        try {
            if ("close".equals(r.operation)) {
                beginCleanup("client_close");
                awaitCleanup(Math.max(1, Math.min(CLEANUP_MS, r.deadline - SystemClock.elapsedRealtime())));
                return response(r, "RELEASED".equals(state), "RELEASED".equals(state) ? null : "CLEANUP_NOT_CONFIRMED", false);
            }
            guard(r, false);
            if(config.profileTarget!=null&&profilePreparing&&!java.util.Arrays.asList("prepare_state","permission_window","prepare_done").contains(r.operation)
                    &&!(config.publicOwnGroupScope!=null&&"display_policy".equals(r.operation)))
                throw new BrokerProtocol.Refusal("PROFILE_PERMISSION_PREPARATION_ACTIVE");
            if(config.publicOwnGroupScope!=null&&"display_policy".equals(r.operation)){
                guard(r,true);return response(r,true,null,false);
            }
            if ("create".equals(r.operation)) {
                if ("ACTIVE".equals(state)) { verifyDisplay(); return response(r, true, null, false); }
                if (!"INITIAL".equals(state)) throw new BrokerProtocol.Refusal("SESSION_NOT_CREATABLE");
                synchronized (dispatchGate) {
                  guard(r, false);
                  createInFlight = true;
                  try {
                    if(config.publicOwnGroupScope!=null&&publicCreateReturnedHandle!=null)
                        throw new BrokerProtocol.Refusal("PUBLIC_CREATE_HANDLE_ALREADY_BOUND");
                    ensureNameAbsent();
                    if(config.profileTarget!=null)profileReadback=profilePreflight(Math.min(r.deadline,expires));
                    final DisplayGeometry geometry = DisplayGeometry.snapshotDefault(displays);
                    displayGeometry = geometry;
                    guard(r, false);
                    displayThread = new HandlerThread("HeptaBackgroundSurface"); displayThread.start();
                    Handler handler = new Handler(displayThread.getLooper());
                    surfaceReader = ImageReader.newInstance(geometry.width, geometry.height, PixelFormat.RGBA_8888, 3);
                    surfaceReader.setOnImageAvailableListener(reader -> {
                        try (Image image = reader.acquireLatestImage()) {
                            if (image == null) return; // Drain without observing or copying pixels.
                        }
                        catch (Throwable error) { if (!closing.get()) shutdown("SURFACE_DRAIN_FAILED"); }
                    }, handler);
                    guard(r, false);
                    dispatched = true;
                    if(config.profileTarget!=null)profileCustody.beforeCreate();
                    if(publicNotesCustody!=null)publicNotesCustody.beforeCreate();
                    // Freeze before create; automatic ON readiness never obtains a new request budget.
                    final long displayInitializationDeadline=Math.min(Math.min(r.deadline,expires),SystemClock.elapsedRealtime()+5000);
                    VirtualDisplay created = displays.createVirtualDisplay(displayName, geometry.width, geometry.height, geometry.density,
                        surfaceReader.getSurface(), virtualFlags);
                    if(config.publicOwnGroupScope!=null)publicCreateReturnedHandle=created;
                    virtual = created;
                    if(config.publicOwnGroupScope!=null&&created!=null&&closing.get())startPublicSurfaceDetach(created);
                    if (created == null) throw new BrokerProtocol.Refusal("DISPLAY_CREATION_FAILED");
                    displayId = created.getDisplay().getDisplayId();
                    if (displayId <= Display.DEFAULT_DISPLAY) throw new BrokerProtocol.Refusal("DEFAULT_DISPLAY_REFUSED");
                    if (closing.get()) throw new BrokerProtocol.Refusal("SESSION_CLOSING");
                    setImePolicy.invoke(windowManager, displayId, imeHide);
                    verifyDisplay();
                    acquirePublicScreenLease(created,displayInitializationDeadline);
                    if(publicNotesCustody!=null){
                        publicNotesCustody.bindDisplay(displayId);
                        publicNotesReader=new PublicPersonalNotesReader(shell,activityTasks,displayId,
                                ()->cleanupStarted.get()?cleanupAt+CLEANUP_MS-100:Math.min(expires,requestDeadline>0?requestDeadline:expires));
                        if(publicNotesReader.uid!=publicNotesCustody.expectedUid())throw new BrokerProtocol.Refusal("NOTES_INSTALLATION_CHANGED");
                    }
                    guard(r, false);
                    state = "ACTIVE";
                  } finally { createInFlight = false; }
                }
            } else if ("state".equals(r.operation)) {
                if ("ACTIVE".equals(state)) {
                    verifyDisplay();
                    if(config.profileTarget!=null){
                        if(profileOwnedTask!=null&&!profileOwnedTask.observeStateUntil(Math.min(r.deadline,expires)-100))throw new BrokerProtocol.Refusal("PROFILE_TASK_NOT_OBSERVED");
                        else if(profileOwnedTask==null)requireUnlaunchedProfileEmpty();
                        if(profileOwnedTask!=null)refreshProfileTaskEvidence();
                    } else {
                        verifyLaunchedLocations(snapshot());
                        if(ownedSingleTask!=null&&!ownedSingleTask.observe())throw new BrokerProtocol.Refusal("OWNED_TASK_NOT_OBSERVED");
                    }
                }
            } else if(config.profileTarget!=null&&"prepare".equals(r.operation)) {
                guard(r,true);
                if(profileOwnedTask!=null||profilePreparing)throw new BrokerProtocol.Refusal("PROFILE_LAUNCH_ALREADY_ATTEMPTED");
                if(r.controllerUi!=null){
                    if(config.publicOwnGroupScope==null||permissionControllerUi!=null)
                        throw new BrokerProtocol.Refusal("CONTROLLER_UI_SCOPE_INVALID");
                    PublicOwnGroupPolicy.Scope scope=config.publicOwnGroupScope;
                    PublicPermissionControllerUi.Session originScope=new PublicPermissionControllerUi.Session(scope.sha256,scope.generation,
                            scope.ownerSha256,scope.appUid,scope.targetUserId,scope.createdElapsedMs,scope.expiresElapsedMs);
                    permissionControllerUi=PublicPermissionControllerUi.bind(r.controllerUi,originScope,
                            config.ownerUid,activeRequestPeerPid,BackgroundTaskOrganizer.readOnlyControllerTask(
                            activityTasks,r.controllerUi.task,r.controllerUi.display,()->Math.min(r.deadline,expires)),displayId,SystemClock.elapsedRealtime());
                }
                permissionPhysicalBaseline=permissionPhysicalFence(r);permissionProjectionBaseline=permissionProjectionCurrent;profilePreparing=true;
                dispatched=launchProfile(r,true);
            } else if(config.profileTarget!=null&&"prepare_state".equals(r.operation)) {
                requirePermissionPreparing(r);
                profilePreparationState=profileOwnedTask.initializationState(Math.min(r.deadline,expires));
                requirePermissionPhysicalUnchanged(permissionPhysicalFence(r));refreshProfileTaskEvidence();
            } else if(config.profileTarget!=null&&"permission_window".equals(r.operation)) {
                requirePermissionPreparing(r);
                java.util.Map<Integer,String> before=permissionPhysicalFence(r);requirePermissionPhysicalUnchanged(before);
                ProfileOwnedTask.PermissionRead read=profileOwnedTask.permissionForInitialization(r.windowId,r.observedTaskId,Math.min(r.deadline,expires));
                java.util.Map<Integer,String> after=permissionPhysicalFence(r);requirePermissionPhysicalUnchanged(after);
                if(config.publicOwnGroupScope==null&&!before.equals(after))throw new BrokerProtocol.Refusal("PROFILE_PERMISSION_PHYSICAL_CHANGED_DURING_READ");
                guard(r,true);permissionWindow=config.publicOwnGroupScope==null
                        ?PermissionWindowObservation.fromLive(read,after,SystemClock.elapsedRealtime())
                        :PermissionWindowObservation.fromLive(read,after,permissionProjectionCurrent,SystemClock.elapsedRealtime());
                permissionWindowRequest=r.requestId;profilePreparationState="PERMISSION_PENDING";refreshProfileTaskEvidence();
            } else if(config.profileTarget!=null&&"prepare_done".equals(r.operation)) {
                requirePermissionPreparing(r);
                boolean wasReady="APP_READY".equals(profilePreparationState);
                profileConfirmationSample="UNAVAILABLE";
                profileConfirmationSample=profileOwnedTask.initializationState(Math.min(r.deadline,expires));
                requirePermissionPhysicalUnchanged(permissionPhysicalFence(r));
                if("APP_READY".equals(profileConfirmationSample)){
                    profileConfirmationSample="UNAVAILABLE";
                    try{
                        profileConfirmationSample=profileOwnedTask.confirmInitializationReady(Math.min(r.deadline,expires))
                                ?"APP_READY":"WAITING";
                    }catch(ProfileTaskPolicy.Refusal refused){
                        if(!ProfileOwnedTask.verifiedPermissionDuringConfirmation(refused))throw refused;
                        profileConfirmationSample="PERMISSION_PENDING";
                    }
                }
                requirePermissionPhysicalUnchanged(permissionPhysicalFence(r));guard(r,true);
                if("APP_READY".equals(profileConfirmationSample)){
                    profilePreparing=false;profilePreparationState="COMPLETE";
                }else{
                    if(!wasReady||profileConfirmationDeferred||!("WAITING".equals(profileConfirmationSample)
                            ||"PERMISSION_PENDING".equals(profileConfirmationSample)))
                        throw new BrokerProtocol.Refusal("PROFILE_PERMISSION_SETUP_REQUIRED");
                    profileConfirmationDeferred=true;profilePreparationState=profileConfirmationSample;
                }
                refreshProfileTaskEvidence();
            } else if(config.profileTarget!=null&&"launch".equals(r.operation)) {
                dispatched=launchProfile(r);
            } else if(config.profileTarget!=null&&"window".equals(r.operation)) {
                guard(r,true);
                if(profileOwnedTask==null)throw new BrokerProtocol.Refusal("PROFILE_TASK_NOT_ACTIVE");
                profileWindow=profileOwnedTask.window(r.windowId,r.observedTaskId,Math.min(r.deadline,expires));
                profileWindowRequest=r.requestId;
                refreshProfileTaskEvidence();
            } else if(config.profileTarget!=null&&"calendar_probe".equals(r.operation)) {
                probeCalendarWindow(r);
            } else if(config.profileTarget!=null&&"calendar_date".equals(r.operation)) {
                // Dedicated authenticated profile operation. The App sends this
                // only through its private one-use ActionWork/Slot-bound attempt.
                dispatched=dispatchCalendarDate(r);
            } else if(config.profileTarget!=null&&"back".equals(r.operation)) {
                dispatched=backProfile(r);
            } else if ("launch".equals(r.operation)||FixedIntentTools.isTool(r.operation)) {
                guard(r, true);
                if(ownedSingleTask!=null)throw new BrokerProtocol.Refusal("OWNED_TASK_LAUNCH_ALREADY_ATTEMPTED");
                TaskSnapshot before = snapshot(); before.requireNoOtherDisplay(r.packageName, displayId);
                final FixedIntentTarget fixedTarget;
                final Intent intent;
                final String resolvedType;
                if(FixedIntentTools.isTool(r.operation)){
                    fixedTarget=FixedIntentDispatch.inspect(shell,config.ownerUid,r.operation);
                    if(fixedTarget.uid!=r.targetUid)throw new BrokerProtocol.Refusal("FIXED_TARGET_UID_CHANGED");
                    intent=FixedIntentDispatch.intent(fixedTarget,r.payload);
                    resolvedType=FixedIntentTools.forAction(r.operation).mimeType;
                }else{
                    fixedTarget=null;resolvedType=null;
                    Intent base = shell.getPackageManager().getLaunchIntentForPackage(r.packageName);
                    if (base == null || base.getComponent() == null
                        || !r.packageName.equals(base.getComponent().getPackageName()))
                        throw new BrokerProtocol.Refusal("PACKAGE_NOT_LAUNCHABLE");
                    ActivityInfo info = shell.getPackageManager().getActivityInfo(base.getComponent(), 0);
                    if (!info.enabled || !info.exported) throw new BrokerProtocol.Refusal("ACTIVITY_NOT_EXPORTED");
                    Intent nativeHome=BackgroundTaskOrganizer.nativeHome(shell,base);
                    intent = nativeHome!=null ? nativeHome : new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
                        .setComponent(base.getComponent()).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_MULTIPLE_TASK);
                }
                final BackgroundOwnedTaskPolicy.Activity initialActivity = launchActivityInfo(
                    intent.getComponent(), r.packageName, fixedTarget == null ? -1 : fixedTarget.uid);
                ActivityOptions options = ActivityOptions.makeBasic().setLaunchDisplayId(displayId);
                synchronized (dispatchGate) {
                    guard(r, true);
                    snapshot().requireNoOtherDisplay(r.packageName, displayId);
                    if (closing.get()) throw new BrokerProtocol.Refusal("SESSION_CLOSING");
                    if(fixedTarget!=null)FixedIntentDispatch.recheck(shell,config.ownerUid,fixedTarget);
                    BackgroundOwnedTaskPolicy.Activity currentActivity = launchActivityInfo(
                        intent.getComponent(), r.packageName, initialActivity.uid);
                    if (!initialActivity.same(currentActivity))
                        throw new BrokerProtocol.Refusal("LAUNCH_ACTIVITY_INFO_CHANGED");
                    guard(r, true);
                    if (BackgroundOwnedSingleTask.eligible(currentActivity,intent.getFlags()) && fixedTarget==null) {
                        if(ownedSingleTask!=null)throw new BrokerProtocol.Refusal("OWNED_TASK_LAUNCH_ALREADY_ATTEMPTED");
                        BackgroundTaskOrganizer.recheckHome(shell,currentActivity);
                        BackgroundTaskOrganizer organizer=new BackgroundTaskOrganizer(activityTasks,options,displayId,
                            () -> { guard(r,true); snapshot().requireNoOtherDisplay(r.packageName,displayId); },
                            () -> { snapshot().requireNoOtherDisplay(r.packageName,displayId); },
                            () -> cleanupStarted.get() ? cleanupAt+CLEANUP_MS-100 : Math.min(r.deadline,expires));
                        ownedSingleTask=new BackgroundOwnedSingleTask(organizer,config.generation,r.requestId,
                            displayId,currentActivity,intent.getFlags());
                        effectInFlight=true;
                        try { ownedSingleTask.prepare(); } finally { effectInFlight=false; }
                        BackgroundOwnedTaskPolicy.Activity preparedActivity=launchActivityInfo(
                            intent.getComponent(),r.packageName,currentActivity.uid);
                        if(!currentActivity.same(preparedActivity))throw new BrokerProtocol.Refusal("LAUNCH_ACTIVITY_INFO_CHANGED");
                        BackgroundTaskOrganizer.recheckHome(shell,preparedActivity);
                        ownedSingleTask.beforeDispatch();
                    } else {
                    BackgroundOwnedTaskPolicy.Plan taskPolicy = BackgroundOwnedTaskPolicy.choose(
                        config.generation, displayId, r.packageName, currentActivity, intent.getFlags());
                    taskLaunchPolicies.put(r.requestId, taskLaunchPolicyEvidence(r, currentActivity, taskPolicy));
                    requireIsolatedTaskLaunch(taskPolicy);
                    intent.setFlags(taskPolicy.outboundFlags);
                    // End unchanged standard/document admission.
                    }
                    if(fixedTarget!=null){
                        if(!fixedToolsConsumed.add(r.operation))throw new BrokerProtocol.Refusal("FIXED_TOOL_ALREADY_CONSUMED");
                        fixedIntentProofs.put(r.requestId,new JSONObject().put("schema","hepta.background-fixed-intent.v1")
                            .put("request_id",r.requestId).put("generation",config.generation).put("display_id",displayId)
                            .put("action",r.operation).put("attempt_id",r.attemptId).put("payload_sha256",FixedIntentTarget.payloadSha256(r.payload))
                            .put("target",new JSONObject(fixedTarget.evidence())).put("ordinary_caller_uid",config.ownerUid)
                            .put("resolved_type",resolvedType==null?JSONObject.NULL:resolvedType).put("attempt_consumed",true)
                            .put("goal_independently_verified",false));
                    }
                    dispatched = true; launched.add(r.packageName);
                    if(publicNotesCustody!=null)publicNotesCustody.markLaunch();
                    effectInFlight = true;
                    try {
                        // systemMain() supplies a Context but does not register this shell process as
                        // an app process. Context.startActivity would forward its unregistered nonnull
                        // ApplicationThread and ActivityStarter rejects that caller. Use the existing
                        // shell/root Binder identity, null app caller, and the fixed user-0 contract.
                        Object launchResult = startActivityAsUser.invoke(activityTasks,
                            null, "com.android.shell", null, intent, resolvedType, null, null, 0, 0,
                            null, options.toBundle(), 0);
                        if (!(launchResult instanceof Integer) || ((Integer) launchResult).intValue() < 0)
                            throw new BrokerProtocol.Refusal("FRAMEWORK_LAUNCH_NOT_ACCEPTED");
                        if(ownedSingleTask!=null)ownedSingleTask.accepted(((Integer)launchResult).intValue());
                        if(publicNotesCustody!=null&&ownedSingleTask==null&&fixedTarget==null)
                            publicNotesCustody.acceptedOrdinaryLaunch(currentActivity.component,SystemClock.elapsedRealtime());
                    }
                    finally { effectInFlight = false; }
                }
                boolean observed = false;
                while (SystemClock.elapsedRealtime() < r.deadline - 100) {
                    guard(r, true);
                    TaskSnapshot after = snapshot(); after.requireNoOtherDisplay(r.packageName, displayId);
                    verifyLaunchedLocations(after);
                    if (r.packageName.equals(after.singleVisibleTop(displayId))
                        && (ownedSingleTask==null || ownedSingleTask.observe())) { observed = true; break; }
                    Thread.sleep(40);
                }
                if (!observed) throw new BrokerProtocol.Refusal("LAUNCH_NOT_OBSERVED_ON_SESSION_DISPLAY");
            } else if ("back".equals(r.operation)) {
                guard(r, true);
                TaskSnapshot current = snapshot(); verifyLaunchedLocations(current);
                String pkg = current.singleVisibleTop(displayId);
                if (pkg == null || !config.packages.contains(pkg)) throw new BrokerProtocol.Refusal("BACK_TARGET_NOT_ALLOWED");
                if (!pkg.equals(r.packageName)) throw new BrokerProtocol.Refusal("BACK_TARGET_CHANGED");
                current.requireNoOtherDisplay(pkg, displayId);
                int uid = shell.getPackageManager().getApplicationInfo(pkg, 0).uid;
                if (uid < 0) throw new BrokerProtocol.Refusal("BACK_TARGET_UID_UNKNOWN");
                guard(r, true);
                long now = SystemClock.uptimeMillis();
                KeyEvent down = new KeyEvent(now, now, KeyEvent.ACTION_DOWN, KeyEvent.KEYCODE_BACK, 0, 0,
                    KeyCharacterMap.VIRTUAL_KEYBOARD, 0, KeyEvent.FLAG_FROM_SYSTEM, InputDevice.SOURCE_KEYBOARD);
                KeyEvent up = new KeyEvent(now, now + 1, KeyEvent.ACTION_UP, KeyEvent.KEYCODE_BACK, 0, 0,
                    KeyCharacterMap.VIRTUAL_KEYBOARD, 0, KeyEvent.FLAG_FROM_SYSTEM, InputDevice.SOURCE_KEYBOARD);
                keyDisplayId.invoke(down, displayId); keyDisplayId.invoke(up, displayId);
                boolean downOk, upOk;
                synchronized (dispatchGate) {
                    guard(r, true);
                    TaskSnapshot fresh = snapshot();
                    if (!r.packageName.equals(fresh.singleVisibleTop(displayId)))
                        throw new BrokerProtocol.Refusal("BACK_TARGET_CHANGED");
                    fresh.requireNoOtherDisplay(r.packageName, displayId);
                    if (closing.get()) throw new BrokerProtocol.Refusal("SESSION_CLOSING");
                    dispatched = true; effectInFlight = true;
                    try {
                        downOk = Boolean.TRUE.equals(injectInput.invoke(inputManager, down, 1, uid));
                        upOk = Boolean.TRUE.equals(injectInput.invoke(inputManager, up, 1, uid));
                    } finally { effectInFlight = false; }
                }
                if (!downOk || !upOk) throw new BrokerProtocol.Refusal("BACK_INJECTION_NOT_CONFIRMED");
                guard(r, true);
            } else throw new BrokerProtocol.Refusal("OPERATION_NOT_ALLOWED");
            guard(r, "ACTIVE".equals(state));
            return response(r, true, null, dispatched);
        } catch (Throwable error) {
            if(config.profileTarget!=null)dispatched|=profileRequestDispatched;
            beginCleanup(code(error));
            awaitCleanup(Math.max(1, Math.min(CLEANUP_MS, r.deadline - SystemClock.elapsedRealtime())));
            serve = false;
            return response(r, false, code(error), dispatched);
        } finally {if(config.profileTarget!=null)activeProfileRequest=null;}
    }

    private void guard(BrokerProtocol.Request r, boolean active) throws Exception {
        r.checkDeadline(SystemClock.elapsedRealtime(), expires);
        if (closing.get()) throw new BrokerProtocol.Refusal("SESSION_CLOSING");
        requireUnlocked();
        if(config.profileTarget!=null)recheckProfile(true,Math.min(r.deadline,expires));
        if (active) {
            if (!"ACTIVE".equals(state)) throw new BrokerProtocol.Refusal("SESSION_NOT_ACTIVE");
            verifyDisplay();
        }
    }

    private void recheckProfile(boolean ready,long deadline)throws Exception {
        if(profilePackages==null)throw new BrokerProtocol.Refusal("PROFILE_PLATFORM_UNAVAILABLE");
        ProfilePackages.Readback actual=profilePackages.read(config.profileTarget.profile.userId,config.profileTarget.packageName,ready,deadline);
        if(!config.profileTarget.same(actual.target))throw new BrokerProtocol.Refusal("PROFILE_INSTALLATION_IDENTITY_CHANGED");
        profileReadback=actual;
    }
    private ProfilePackages.Readback profilePreflight(long deadline)throws Exception{
        if(config.publicOwnGroupScope==null)return ProfileTaskPlatform.preflight(activityTasks,profilePackages,config.profileTarget,deadline);
        ProfilePackages.Readback actual=ProfileTaskPlatform.publicPreflight(activityTasks,profilePackages,config.profileTarget,deadline);
        String raw=BackgroundTaskOrganizer.profileRecents(()->deadline);
        if(publicProfileHistory==null)publicProfileHistory=new PublicProfileRecentHistory.Baseline(PublicProfileRecentHistory.absence(raw,actual.target),SystemClock.elapsedRealtime());
        else publicProfileHistory.requireTargetAbsent(raw,actual.target,SystemClock.elapsedRealtime());
        // Both actual Binder samples still require every target-profile live root/leaf absent.
        BackgroundTaskOrganizer.profileSnapshot(activityTasks).requireDedicatedEmpty(actual.target);return actual;
    }
    private long profileDeadline(){
        Long retainedDeadline=retainedReadDeadline.get();
        if(retainedDeadline!=null)return retainedDeadline.longValue();
        return cleanupStarted.get()?cleanupAt+CLEANUP_MS-100:
                Math.min(expires,requestDeadline>0?requestDeadline:started+STARTUP_MS);
    }
    private void profileActiveGuard()throws Exception {
        BrokerProtocol.Request request=activeProfileRequest;
        if(request==null)throw new BrokerProtocol.Refusal("PROFILE_ACTIVE_REQUEST_MISSING");
        guard(request,true);
    }
    private void requireUnlaunchedProfileEmpty()throws Exception {
        ProfileTaskPolicy.Snapshot snapshot=BackgroundTaskOrganizer.profileSnapshot(activityTasks);
        snapshot.requireDedicatedEmpty(config.profileTarget);
        String raw=BackgroundTaskOrganizer.profileRecents(()->profileDeadline());
        if(config.publicOwnGroupScope==null)ProfileTaskPolicy.Recents.parse(raw).requireDedicatedEmpty(config.profileTarget);
        else{
            if(publicProfileHistory==null)throw new BrokerProtocol.Refusal("PUBLIC_HISTORY_BASELINE_UNAVAILABLE");
            publicProfileHistory.requireTargetAbsent(raw,config.profileTarget,SystemClock.elapsedRealtime());
        }
        for(ProfileTaskPolicy.Root root:snapshot.roots)if(root.display==displayId)
            throw new BrokerProtocol.Refusal("PROFILE_FOREIGN_ROOT_ON_DISPLAY");
    }
    private void requirePermissionPreparing(BrokerProtocol.Request r)throws Exception{
        guard(r,true);
        if(!profilePreparing||profileOwnedTask==null||permissionPhysicalBaseline==null)
            throw new BrokerProtocol.Refusal("PROFILE_PERMISSION_PREPARATION_NOT_ACTIVE");
    }
    private java.util.Map<Integer,String> permissionPhysicalFence(BrokerProtocol.Request r)throws Exception{
        if(config.publicOwnGroupScope!=null){
            guard(r,true);if(permissionControllerUi!=null)permissionControllerUi.requirePeer(config.ownerUid,activeRequestPeerPid);
            PublicOwnGroupPhysicalReader.InitializationRead value=PublicOwnGroupPhysicalReader.readInitialization(windowManager,displays,activityTasks,
                    publicOwnGroupFramework,config.publicOwnGroupScope,config.profileTarget,displayId,displayName,permissionControllerUi,()->Math.min(r.deadline,expires));
            guard(r,true);permissionProjectionCurrent=value.projection;permissionPhysicalAudit=value.physicalAudit;return value.physicalAudit;
        }
        if(permissionControllerUi!=null){
            guard(r,true);permissionControllerUi.requirePeer(config.ownerUid,activeRequestPeerPid);
            java.util.Map<Integer,String> value=PublicOwnGroupPhysicalReader.readControllerInitialization(windowManager,displays,
                    activityTasks,config.profileTarget.profile.userId,permissionControllerUi,()->Math.min(r.deadline,expires));
            guard(r,true);return value;
        }
        guard(r,true);java.util.Map<Integer,String> value=config.publicOwnGroupScope==null?
                ProfilePermissionPhysicalReader.read(windowManager,displays,config.profileTarget.profile.userId,()->Math.min(r.deadline,expires)):
                PublicOwnGroupPhysicalReader.read(windowManager,displays,config.profileTarget.profile.userId,()->Math.min(r.deadline,expires));
        guard(r,true);return value;
    }
    private void requirePermissionPhysicalUnchanged(java.util.Map<Integer,String> actual)throws Exception{
        if(config.publicOwnGroupScope!=null){
            if(permissionPhysicalBaseline==null||actual==null||actual!=permissionPhysicalAudit||permissionProjectionBaseline==null
                    ||!permissionProjectionBaseline.same(permissionProjectionCurrent))
                throw new BrokerProtocol.Refusal("PROFILE_PERMISSION_PUBLIC_OWNERSHIP_CHANGED");
            return;
        }
        if(permissionPhysicalBaseline==null||!permissionPhysicalBaseline.equals(actual))
            throw new BrokerProtocol.Refusal("PROFILE_PERMISSION_PHYSICAL_DISPLAY_CHANGED");
    }
    private boolean launchProfile(BrokerProtocol.Request r)throws Exception{return launchProfile(r,false);}
    private boolean launchProfile(BrokerProtocol.Request r,boolean initialization)throws Exception {
        guard(r,true);
        if(profileOwnedTask!=null)throw new BrokerProtocol.Refusal("PROFILE_LAUNCH_ALREADY_ATTEMPTED");
        final ProfileTaskPolicy.Activity initial=profileReadback.activity;
        initial.requireEligible(config.profileTarget);
        final Intent intent=ProfilePackages.launchIntent(profileReadback.target);
        final ActivityOptions options=ActivityOptions.makeBasic().setLaunchDisplayId(displayId);
        synchronized(dispatchGate){
            guard(r,true);requireUnlaunchedProfileEmpty();
            if(!initial.same(profileReadback.activity))throw new BrokerProtocol.Refusal("PROFILE_ACTIVITY_INFO_CHANGED");
            profilePlatform=new ProfileTaskPlatform(activityTasks,options,displayId,profilePackages,
                    config.profileTarget,()->profileActiveGuard(),()->profileDeadline());
            profileOwnedTask=new ProfileOwnedTask(profilePlatform,config.profileTarget,config.generation,r.requestId,displayId,publicProfileHistory);
            effectInFlight=true;
            try{profileOwnedTask.prepare();}finally{effectInFlight=false;}
            guard(r,true);
            if(!initial.same(profileReadback.activity))throw new BrokerProtocol.Refusal("PROFILE_ACTIVITY_INFO_CHANGED");
            profileOwnedTask.beforeDispatch();
            profileRequestDispatched=true;effectInFlight=true;
            try{
                // Explicit target user under the existing root Binder identity. No current-user
                // fallback, task-ID override, reparenting, user switch or cross-profile intent proxy.
                Object result=startActivityAsUser.invoke(activityTasks,null,"com.android.shell",null,
                        intent,null,null,null,0,0,null,options.toBundle(),config.profileTarget.profile.userId);
                if(!(result instanceof Integer))throw new BrokerProtocol.Refusal("PROFILE_START_RESULT_UNAVAILABLE");
                profileOwnedTask.accepted((Integer)result);
                launched.add(r.packageName);
            }finally{effectInFlight=false;}
        }
        boolean observed=false;
        while(SystemClock.elapsedRealtime()<Math.min(r.deadline,expires)-100){
            guard(r,true);
            if(initialization){
                profilePreparationState=profileOwnedTask.initializationState(Math.min(r.deadline,expires));
                if(!"WAITING".equals(profilePreparationState)){observed=true;break;}
            }else if(profileOwnedTask.observe()){observed=true;break;}
            Thread.sleep(40);
        }
        if(!observed)throw new BrokerProtocol.Refusal("PROFILE_LAUNCH_NOT_OBSERVED");
        if(initialization)requirePermissionPhysicalUnchanged(permissionPhysicalFence(r));
        refreshProfileTaskEvidence();
        return true;
    }
    /** Read-only ROM qualification. It cannot consume a calendar model intent or inject input. */
    private void probeCalendarWindow(BrokerProtocol.Request r)throws Exception {
        final long entered=SystemClock.elapsedRealtime();
        final long deadline=Math.min(Math.min(r.deadline,expires),entered>Long.MAX_VALUE-4000?Long.MAX_VALUE:entered+4000);
        final java.util.Map<String,Object> proof=new java.util.LinkedHashMap<String,Object>();
        proof.put("schema","hepta.calendar-window-probe.v1");proof.put("request_id",r.requestId);
        proof.put("generation",config.generation);proof.put("target_sha256",r.profileTargetSha256);
        proof.put("display_scope_sha256",r.displayScopeSha256);proof.put("entered_elapsed_ms",entered);
        proof.put("original_request_deadline_elapsed_ms",r.deadline);proof.put("probe_deadline_elapsed_ms",deadline);
        proof.put("grants_dispatch",false);proof.put("input_attempts",0);proof.put("dispatched",false);
        proof.put("calendar_date_effect_integrated",false);proof.put("qualified",false);
        proof.put("phase","admission");
        calendarProbeRequest=r.requestId;calendarProbeEvidence=new JSONObject(proof);
        WindowInfosCapture capture=null;Throwable firstFailure=null;
        try{
            if(config.publicOwnGroupScope==null||config.profileTarget==null
                    ||!ProfileTarget.CTRIP.equals(config.profileTarget.packageName)
                    ||!ProfileTarget.CTRIP.equals(r.packageName)||r.windowId<0||r.observedTaskId<=0)
                throw new BrokerProtocol.Refusal("CALENDAR_PROBE_SCOPE_REQUIRED");
            guard(r,true);
            if(profileOwnedTask==null)throw new BrokerProtocol.Refusal("PROFILE_TASK_NOT_ACTIVE");
            WindowOwnership first=profileOwnedTask.window(r.windowId,r.observedTaskId,deadline);
            first.requireMatches(config.profileTarget,config.generation,displayId,r.windowId,r.observedTaskId,SystemClock.elapsedRealtime());
            DisplayGeometry geometry=DisplayGeometry.read(displays.getDisplay(displayId),displayId);
            if(!displayName.equals(geometry.name))throw new BrokerProtocol.Refusal("INPUT_OWNED_DISPLAY_CHANGED");
            AccessibilityWindowTokens.Read before=AccessibilityWindowTokens.read(profilePackages,profileReadback.target,r.windowId,deadline);
            proof.put("namespace_before",new JSONObject(before.evidence()));proof.put("owned_window_before",new JSONObject(first.evidence()));
            proof.put("display_before",new JSONObject(geometry.evidence()));
            synchronized(dispatchGate){
                guard(r,true);
                if(calendarWindowCapture!=null)throw new BrokerProtocol.Refusal("INPUT_LISTENER_SLOT_OCCUPIED");
                capture=new WindowInfosCapture(deadline);calendarWindowCapture=capture;
            }
            proof.put("phase","register_and_callback");capture.register();
            InputChannelIsolation.Census census=capture.awaitCallback();
            proof.put("phase","current_window_binding");capture.requireCurrent(census);
            guard(r,true);
            WindowOwnership fresh=profileOwnedTask.window(r.windowId,r.observedTaskId,deadline);
            fresh.requireMatches(config.profileTarget,config.generation,displayId,r.windowId,r.observedTaskId,SystemClock.elapsedRealtime());
            if(first.taskId!=fresh.taskId||first.parentTaskId!=fresh.parentTaskId||first.fullUid!=fresh.fullUid
                    ||!first.taskTokenId.equals(fresh.taskTokenId))throw new BrokerProtocol.Refusal("INPUT_OWNED_TASK_CHANGED");
            AccessibilityWindowTokens.Read after=AccessibilityWindowTokens.read(profilePackages,profileReadback.target,r.windowId,deadline);
            before.requireSame(after);
            DisplayGeometry finalGeometry=DisplayGeometry.read(displays.getDisplay(displayId),displayId);
            if(!geometry.sameSize(finalGeometry)||geometry.rotation!=finalGeometry.rotation
                    ||!geometry.name.equals(finalGeometry.name))throw new BrokerProtocol.Refusal("INPUT_OWNED_DISPLAY_CHANGED");
            InputChannelIsolation.Match match;
            synchronized(dispatchGate){
                guard(r,true);
                if(calendarWindowCapture!=capture)throw new BrokerProtocol.Refusal("INPUT_LISTENER_OWNER_CHANGED");
                capture.requireCurrent(census);
                fresh.requireMatches(config.profileTarget,config.generation,displayId,r.windowId,r.observedTaskId,SystemClock.elapsedRealtime());
                match=InputChannelIsolation.inspect(census,new InputChannelIsolation.Expected(displayId,
                        profileReadback.target.fullUid,profileReadback.target.profile.userId,after.namespaceUserId,
                        r.windowId,r.observedTaskId,r.packageName,finalGeometry.width,finalGeometry.height,
                        finalGeometry.rotation,after.token),SystemClock.elapsedRealtime(),deadline);
                if(!(match.target.inputToken instanceof IBinder)||!((IBinder)match.target.inputToken).isBinderAlive())
                    throw new BrokerProtocol.Refusal("INPUT_CHANNEL_TOKEN_NOT_LIVE");
                capture.requireCurrent(census);
            }
            proof.put("namespace_after",new JSONObject(after.evidence()));proof.put("owned_window_after",new JSONObject(fresh.evidence()));
            proof.put("display_after",new JSONObject(finalGeometry.evidence()));proof.put("isolation",new JSONObject(match.evidence()));
            proof.put("phase","unregister_and_local_drain");
        }catch(Throwable error){
            firstFailure=error;proof.put("first_failure",code(error));
            if(error instanceof Exception)throw (Exception)error;if(error instanceof Error)throw (Error)error;
            throw new IllegalStateException(error);
        }finally{
            if(capture!=null){
                try{capture.unregisterAndDrain(Math.min(expires,r.deadline));}
                catch(InputChannelIsolation.Refusal closingFailure){
                    proof.put("listener_close_failure",closingFailure.code);
                    if(firstFailure==null){firstFailure=closingFailure;proof.put("first_failure",closingFailure.code);}
                }
                proof.put("listener_lifecycle",new JSONObject(capture.evidence()));
                synchronized(dispatchGate){if(calendarWindowCapture==capture&&capture.locallyDrained())calendarWindowCapture=null;}
            }
            proof.put("read_finished_elapsed_ms",SystemClock.elapsedRealtime());calendarProbeEvidence=new JSONObject(proof);
        }
        if(firstFailure!=null){
            if(firstFailure instanceof Exception)throw (Exception)firstFailure;
            throw new IllegalStateException(firstFailure);
        }
        if(SystemClock.elapsedRealtime()>=deadline)throw new BrokerProtocol.Refusal("INPUT_PROBE_DEADLINE");
        if(capture==null||!capture.locallyDrained())throw new BrokerProtocol.Refusal("INPUT_LISTENER_DRAIN_UNKNOWN");
        proof.put("qualified",true);proof.put("phase","readonly_window_channel_isolation_verified");
        proof.put("qualified_elapsed_ms",SystemClock.elapsedRealtime());calendarProbeEvidence=new JSONObject(proof);
    }

    /**
     * Dedicated calendar_date implementation reached only from that perform branch.
     * Current owner/window/channel qualification still runs before the one DOWN.
     * The authenticated wire is intent data, not a substitute for the App's
     * private one-use CalendarInputAttempt from the original ActionWork/Slot.
     */
    private boolean dispatchCalendarDate(BrokerProtocol.Request r)throws Exception{
        final long entered=SystemClock.elapsedRealtime();
        final long deadline=Math.min(Math.min(r.deadline,expires),entered>Long.MAX_VALUE-4000?Long.MAX_VALUE:entered+4000);
        final BrokerProtocol.CalendarDate date=r.calendarDate;
        final java.util.Map<String,Object> proof=new java.util.LinkedHashMap<String,Object>();
        proof.put("schema","hepta.calendar-date-input-attempt.v1");proof.put("request_id",r.requestId);
        proof.put("generation",config.generation);proof.put("display_id",displayId);
        proof.put("entered_elapsed_ms",entered);proof.put("original_request_deadline_elapsed_ms",r.deadline);
        proof.put("effect_deadline_elapsed_ms",deadline);proof.put("effect_route_integrated",true);
        proof.put("attempt_consumed",false);proof.put("down_attempted",false);proof.put("down_returned_true",false);
        proof.put("up_attempted",false);proof.put("up_returned_true",false);proof.put("cancel_attempted",false);
        proof.put("second_down_attempted",false);proof.put("date_independently_verified",false);
        proof.put("business_completion_verified",false);proof.put("phase","admission");
        calendarDateRequest=r.requestId;calendarDateEvidence=new JSONObject(proof);
        WindowInfosCapture capture=null;Throwable firstFailure=null;boolean pairAccepted=false;
        MotionEvent down=null,up=null;
        try{
            if(config.publicOwnGroupScope==null||config.profileTarget==null||date==null
                    ||!ProfileTarget.CTRIP.equals(config.profileTarget.packageName)
                    ||!ProfileTarget.CTRIP.equals(r.packageName)
                    ||!date.ownerTaskId.equals(config.publicOwnGroupScope.taskId)
                    ||r.windowId<0||r.observedTaskId<=0)
                throw new BrokerProtocol.Refusal("CALENDAR_DATE_SCOPE_REQUIRED");
            proof.put("owner_task_id",date.ownerTaskId);proof.put("goal_sha256",date.goalSha256);proof.put("date",date.date);
            proof.put("observation_id",date.observationId);proof.put("screen_sha256",date.screenSha256);
            proof.put("permit_sha256",date.permitSha256);proof.put("attempt_record_sha256",date.attemptRecordSha256);
            proof.put("rectangle",java.util.Arrays.asList(date.left,date.top,date.right,date.bottom));
            proof.put("profile_target_sha256",r.profileTargetSha256);proof.put("display_scope_sha256",r.displayScopeSha256);
            guard(r,true);
            if(profileOwnedTask==null)throw new BrokerProtocol.Refusal("PROFILE_TASK_NOT_ACTIVE");
            WindowOwnership first=profileOwnedTask.window(r.windowId,r.observedTaskId,deadline);
            first.requireMatches(config.profileTarget,config.generation,displayId,r.windowId,r.observedTaskId,SystemClock.elapsedRealtime());
            DisplayGeometry geometry=DisplayGeometry.read(displays.getDisplay(displayId),displayId);
            if(!displayName.equals(geometry.name)||geometry.width!=date.width||geometry.height!=date.height
                    ||geometry.rotation!=date.rotation)throw new BrokerProtocol.Refusal("CALENDAR_DISPLAY_GEOMETRY_CHANGED");
            AccessibilityWindowTokens.Read before=AccessibilityWindowTokens.read(profilePackages,profileReadback.target,r.windowId,deadline);
            proof.put("namespace_before",new JSONObject(before.evidence()));
            proof.put("owned_window_before",new JSONObject(first.evidence()));
            proof.put("display_before",new JSONObject(geometry.evidence()));

            // Resolve the real bootclasspath field. No guessed integer fallback.
            int noFocusChange=calendarPlatformInt(MotionEvent.class,"FLAG_NO_FOCUS_CHANGE");
            if(noFocusChange<=0||(noFocusChange&(noFocusChange-1))!=0)
                throw new BrokerProtocol.Refusal("CALENDAR_NO_FOCUS_CHANGE_UNAVAILABLE");
            int waitForResult=calendarPlatformInt(Class.forName("android.hardware.input.InputManager"),
                    "INJECT_INPUT_EVENT_MODE_WAIT_FOR_RESULT");
            if(waitForResult!=1)throw new BrokerProtocol.Refusal("CALENDAR_WAIT_FOR_RESULT_UNSUPPORTED");
            Method setMotionDisplay=MotionEvent.class.getMethod("setDisplayId",int.class);
            Method getMotionDisplay=MotionEvent.class.getMethod("getDisplayId");
            proof.put("no_focus_change_platform_value",noFocusChange);
            proof.put("injection_mode_platform_value",waitForResult);
            proof.put("requested_device_id",KeyCharacterMap.VIRTUAL_KEYBOARD);
            proof.put("dispatcher_device_id_isolation_claimed",false);
            synchronized(dispatchGate){
                guard(r,true);
                if(calendarWindowCapture!=null)throw new BrokerProtocol.Refusal("INPUT_LISTENER_SLOT_OCCUPIED");
                capture=new WindowInfosCapture(deadline);calendarWindowCapture=capture;
            }
            proof.put("phase","fresh_register_and_callback");calendarDateEvidence=new JSONObject(proof);
            capture.register();InputChannelIsolation.Census census=capture.awaitCallback();
            capture.requireCurrent(census);guard(r,true);
            WindowOwnership fresh=profileOwnedTask.window(r.windowId,r.observedTaskId,deadline);
            fresh.requireMatches(config.profileTarget,config.generation,displayId,r.windowId,r.observedTaskId,SystemClock.elapsedRealtime());
            if(first.taskId!=fresh.taskId||first.parentTaskId!=fresh.parentTaskId||first.fullUid!=fresh.fullUid
                    ||!first.taskTokenId.equals(fresh.taskTokenId))throw new BrokerProtocol.Refusal("INPUT_OWNED_TASK_CHANGED");
            AccessibilityWindowTokens.Read after=AccessibilityWindowTokens.read(profilePackages,profileReadback.target,r.windowId,deadline);
            before.requireSame(after);
            DisplayGeometry finalGeometry=DisplayGeometry.read(displays.getDisplay(displayId),displayId);
            if(!geometry.sameSize(finalGeometry)||geometry.rotation!=finalGeometry.rotation
                    ||!geometry.name.equals(finalGeometry.name))throw new BrokerProtocol.Refusal("INPUT_OWNED_DISPLAY_CHANGED");
            proof.put("namespace_after",new JSONObject(after.evidence()));
            proof.put("owned_window_after",new JSONObject(fresh.evidence()));
            proof.put("display_after",new JSONObject(finalGeometry.evidence()));
            synchronized(dispatchGate){
                // This gate excludes this broker's own cleanup/effect races.
                // It is not an atomic SurfaceFlinger/InputDispatcher epoch CAS.
                guard(r,true);
                if(calendarWindowCapture!=capture)throw new BrokerProtocol.Refusal("INPUT_LISTENER_OWNER_CHANGED");
                capture.requireCurrent(census);
                fresh.requireMatches(config.profileTarget,config.generation,displayId,r.windowId,r.observedTaskId,SystemClock.elapsedRealtime());
                InputChannelIsolation.Match match=InputChannelIsolation.inspect(census,new InputChannelIsolation.Expected(displayId,
                        profileReadback.target.fullUid,profileReadback.target.profile.userId,after.namespaceUserId,
                        r.windowId,r.observedTaskId,r.packageName,finalGeometry.width,finalGeometry.height,
                        finalGeometry.rotation,after.token),SystemClock.elapsedRealtime(),deadline);
                if(!(match.target.inputToken instanceof IBinder)||!((IBinder)match.target.inputToken).isBinderAlive())
                    throw new BrokerProtocol.Refusal("INPUT_CHANNEL_TOKEN_NOT_LIVE");
                double[] point=InputChannelIsolation.calendarPoint(match,date,SystemClock.elapsedRealtime(),deadline);
                int actualFullUid=profileReadback.target.fullUid;
                proof.put("target_full_uid",actualFullUid);proof.put("isolation",new JSONObject(match.evidence()));
                proof.put("logical_point",java.util.Arrays.asList(point[0],point[1]));
                long downTime=SystemClock.uptimeMillis();
                down=calendarMotion(downTime,downTime,MotionEvent.ACTION_DOWN,point,noFocusChange,
                        setMotionDisplay,getMotionDisplay);
                // All blocking owner/window checks preceded this final fence.
                capture.requireCurrent(census);
                fresh.requireMatches(config.profileTarget,config.generation,displayId,r.windowId,r.observedTaskId,SystemClock.elapsedRealtime());
                if(closing.get()||publicAdmissionRetired.get()||SystemClock.elapsedRealtime()>=deadline)
                    throw new BrokerProtocol.Refusal("CALENDAR_DATE_RETIRED_BEFORE_DOWN");
                if(!calendarDateConsumed.compareAndSet(false,true))
                    throw new BrokerProtocol.Refusal("CALENDAR_DATE_ALREADY_CONSUMED");
                proof.put("attempt_consumed",true);proof.put("consumed_elapsed_ms",SystemClock.elapsedRealtime());
                proof.put("phase","down_attempted");proof.put("down_attempted",true);
                proof.put("down_time_uptime_ms",downTime);proof.put("down_attempted_elapsed_ms",SystemClock.elapsedRealtime());
                calendarDateEvidence=new JSONObject(proof);
                profileRequestDispatched=true;effectInFlight=true;
                try{
                    // Same actual targeted overload as profile BACK. No uid-less
                    // overload, default-display fallback, or host input path.
                    Object result=injectInput.invoke(inputManager,down,waitForResult,actualFullUid);
                    if(!Boolean.TRUE.equals(result)){
                        proof.put("phase","down_not_confirmed_owned_cleanup_only");calendarDateEvidence=new JSONObject(proof);
                        throw new BrokerProtocol.Refusal("CALENDAR_DOWN_NOT_CONFIRMED");
                    }
                    proof.put("down_returned_true",true);proof.put("down_returned_elapsed_ms",SystemClock.elapsedRealtime());
                    proof.put("phase","down_accepted");calendarDateEvidence=new JSONObject(proof);
                    // Only an explicitly true DOWN return permits this same
                    // pointer's single bounded UP. Any error/false/unknown
                    // before this point has NO UP, CANCEL, or second DOWN.
                    guard(r,true);capture.requireCurrent(census);
                    fresh.requireMatches(config.profileTarget,config.generation,displayId,r.windowId,r.observedTaskId,SystemClock.elapsedRealtime());
                    if(calendarWindowCapture!=capture||closing.get()||publicAdmissionRetired.get()
                            ||SystemClock.elapsedRealtime()>=deadline)
                        throw new BrokerProtocol.Refusal("CALENDAR_DATE_RETIRED_BEFORE_UP");
                    long upTime=SystemClock.uptimeMillis();
                    if(upTime<downTime)throw new BrokerProtocol.Refusal("CALENDAR_UPTIME_REGRESSED");
                    up=calendarMotion(downTime,upTime,MotionEvent.ACTION_UP,point,noFocusChange,
                            setMotionDisplay,getMotionDisplay);
                    capture.requireCurrent(census);
                    if(SystemClock.elapsedRealtime()>=deadline||closing.get()||publicAdmissionRetired.get())
                        throw new BrokerProtocol.Refusal("CALENDAR_DATE_RETIRED_BEFORE_UP");
                    proof.put("phase","up_attempted");proof.put("up_attempted",true);
                    proof.put("up_time_uptime_ms",upTime);proof.put("up_attempted_elapsed_ms",SystemClock.elapsedRealtime());
                    calendarDateEvidence=new JSONObject(proof);
                    Object upResult=injectInput.invoke(inputManager,up,waitForResult,actualFullUid);
                    if(!Boolean.TRUE.equals(upResult))throw new BrokerProtocol.Refusal("CALENDAR_UP_NOT_CONFIRMED");
                    proof.put("up_returned_true",true);proof.put("up_returned_elapsed_ms",SystemClock.elapsedRealtime());
                    pairAccepted=true;proof.put("phase","input_pair_accepted_date_unverified");
                    calendarDateEvidence=new JSONObject(proof);
                }finally{effectInFlight=false;}
            }
        }catch(Throwable error){
            firstFailure=error;proof.put("first_failure",code(error));
            if(Boolean.TRUE.equals(proof.get("down_attempted"))&&!Boolean.TRUE.equals(proof.get("down_returned_true")))
                proof.put("phase","down_outcome_unknown_owned_cleanup_only");
            if(error instanceof Exception)throw (Exception)error;if(error instanceof Error)throw (Error)error;
            throw new IllegalStateException(error);
        }finally{
            if(down!=null)down.recycle();if(up!=null)up.recycle();
            if(capture!=null){
                try{capture.unregisterAndDrain(deadline);}
                catch(InputChannelIsolation.Refusal closeFailure){
                    proof.put("listener_close_failure",closeFailure.code);
                    if(firstFailure==null){firstFailure=closeFailure;proof.put("first_failure",closeFailure.code);}
                }
                proof.put("listener_lifecycle",new JSONObject(capture.evidence()));
                synchronized(dispatchGate){if(calendarWindowCapture==capture&&capture.locallyDrained())calendarWindowCapture=null;}
            }
            proof.put("finished_elapsed_ms",SystemClock.elapsedRealtime());proof.put("input_pair_accepted",pairAccepted);
            calendarDateEvidence=new JSONObject(proof);
        }
        if(firstFailure!=null){if(firstFailure instanceof Exception)throw (Exception)firstFailure;throw new IllegalStateException(firstFailure);}
        if(!pairAccepted||capture==null||!capture.locallyDrained())
            throw new BrokerProtocol.Refusal("CALENDAR_DATE_INPUT_OR_DRAIN_UNKNOWN");
        if(SystemClock.elapsedRealtime()>=deadline)throw new BrokerProtocol.Refusal("CALENDAR_DATE_DEADLINE");
        return true; // Transport acknowledgement only; fresh FORM date proof remains mandatory.
    }

    private static int calendarPlatformInt(Class<?> type,String name)throws Exception{
        java.lang.reflect.Field f=type.getField(name);int modifiers=f.getModifiers();
        if(f.getType()!=Integer.TYPE||!java.lang.reflect.Modifier.isStatic(modifiers)
                ||!java.lang.reflect.Modifier.isFinal(modifiers))
            throw new BrokerProtocol.Refusal("CALENDAR_PLATFORM_CONSTANT_UNAVAILABLE");
        return f.getInt(null);
    }

    private MotionEvent calendarMotion(long downTime,long when,int action,double[] point,int flags,
            Method setDisplay,Method getDisplay)throws Exception{
        if(displayId<=1||point==null||point.length!=2||!Double.isFinite(point[0])||!Double.isFinite(point[1])
                ||(action!=MotionEvent.ACTION_DOWN&&action!=MotionEvent.ACTION_UP))
            throw new BrokerProtocol.Refusal("CALENDAR_MOTION_ARGUMENT_INVALID");
        MotionEvent.PointerProperties properties=new MotionEvent.PointerProperties();
        properties.id=0;properties.toolType=MotionEvent.TOOL_TYPE_FINGER;
        MotionEvent.PointerCoords coords=new MotionEvent.PointerCoords();
        coords.x=(float)point[0];coords.y=(float)point[1];coords.pressure=action==MotionEvent.ACTION_UP?0f:1f;coords.size=1f;
        MotionEvent event=MotionEvent.obtain(downTime,when,action,1,new MotionEvent.PointerProperties[]{properties},
                new MotionEvent.PointerCoords[]{coords},0,0,1f,1f,KeyCharacterMap.VIRTUAL_KEYBOARD,0,
                InputDevice.SOURCE_TOUCHSCREEN,flags);
        boolean valid=false;
        try{
            setDisplay.invoke(event,displayId);
            Object actualDisplay=getDisplay.invoke(event);
            if(!(actualDisplay instanceof Integer)||((Integer)actualDisplay).intValue()!=displayId
                    ||event.getPointerCount()!=1||event.getPointerId(0)!=0||event.getActionMasked()!=action
                    ||event.getSource()!=InputDevice.SOURCE_TOUCHSCREEN||event.getFlags()!=flags
                    ||event.getDeviceId()!=KeyCharacterMap.VIRTUAL_KEYBOARD)
                throw new BrokerProtocol.Refusal("CALENDAR_MOTION_BINDING_CHANGED");
            valid=true;return event;
        }finally{if(!valid)event.recycle();}
    }

    private boolean backProfile(BrokerProtocol.Request r)throws Exception {
        guard(r,true);
        if(profileOwnedTask==null||!profileOwnedTask.observe())throw new BrokerProtocol.Refusal("PROFILE_BACK_TARGET_UNAVAILABLE");
        long now=SystemClock.uptimeMillis();
        KeyEvent down=new KeyEvent(now,now,KeyEvent.ACTION_DOWN,KeyEvent.KEYCODE_BACK,0,0,
                KeyCharacterMap.VIRTUAL_KEYBOARD,0,KeyEvent.FLAG_FROM_SYSTEM,InputDevice.SOURCE_KEYBOARD);
        KeyEvent up=new KeyEvent(now,now+1,KeyEvent.ACTION_UP,KeyEvent.KEYCODE_BACK,0,0,
                KeyCharacterMap.VIRTUAL_KEYBOARD,0,KeyEvent.FLAG_FROM_SYSTEM,InputDevice.SOURCE_KEYBOARD);
        keyDisplayId.invoke(down,displayId);keyDisplayId.invoke(up,displayId);
        boolean downOk,upOk;
        synchronized(dispatchGate){
            guard(r,true);
            if(!profileOwnedTask.observe())throw new BrokerProtocol.Refusal("PROFILE_BACK_TARGET_CHANGED");
            int actualUid=profileReadback.target.fullUid;
            profileRequestDispatched=true;effectInFlight=true;
            try{
                downOk=Boolean.TRUE.equals(injectInput.invoke(inputManager,down,1,actualUid));
                upOk=Boolean.TRUE.equals(injectInput.invoke(inputManager,up,1,actualUid));
            }finally{effectInFlight=false;}
        }
        if(!downOk||!upOk)throw new BrokerProtocol.Refusal("PROFILE_BACK_INJECTION_NOT_CONFIRMED");
        guard(r,true);
        if(!profileOwnedTask.observe())throw new BrokerProtocol.Refusal("PROFILE_BACK_RESULT_NOT_OBSERVED");
        refreshProfileTaskEvidence();
        return true;
    }

    private void requireUnlocked() throws BrokerProtocol.Refusal {
        if(config.publicOwnGroupScope!=null){
            if(publicAdmissionRetired.get())throw new BrokerProtocol.Refusal("PUBLIC_SCOPE_RETIRED");
            PublicPolicyFailureAudit.Phase phase=PublicPolicyFailureAudit.Phase.FRAMEWORK_SELECTION;
            try{
                PublicOwnGroupFramework framework=publicOwnGroupFramework;
                if(framework==null)throw new BrokerProtocol.Refusal("PUBLIC_SCOPE_FRAMEWORK_UNAVAILABLE");
                if(publicOwnGroupDisplayReady){
                    phase=PublicPolicyFailureAudit.Phase.FRAMEWORK_READ;
                    framework.read(config.generation,displayId,displayName);
                    if("ACTIVE".equals(state)){
                        phase=PublicPolicyFailureAudit.Phase.SCREEN_LEASE;
                        publicScreenLease.requireActive();
                    }
                }
                else{
                    phase=PublicPolicyFailureAudit.Phase.FRAMEWORK_PREFLIGHT;
                    framework.preflight();
                }
                // New personal mode keeps the original package-location rule on
                // fresh policy reads too; user activity in other apps stays free.
                if(config.profileTarget==null&&displayId>1){
                    phase=PublicPolicyFailureAudit.Phase.PERSONAL_TASK_LOCATION;
                    verifyLaunchedLocations(snapshot());
                }
                PublicOwnGroupTaskFence taskFence=publicTaskFence;
                if(taskFence!=null&&displayId>1){
                    phase=PublicPolicyFailureAudit.Phase.TASK_LOCATION_CENSUS;
                    taskFence.observe(BackgroundTaskOrganizer.publicTaskLocations(activityTasks),displayId,SystemClock.elapsedRealtime());
                }
                if(publicNotesCustody!=null&&publicNotesReader!=null){
                    phase=PublicPolicyFailureAudit.Phase.NOTES_FRAME_AND_CUSTODY;
                    publicNotesCustody.observe(publicNotesReader.frame(publicNotesCustody),SystemClock.elapsedRealtime());
                }
                lastUnlockedCheck=SystemClock.elapsedRealtime();return;
            }catch(BrokerProtocol.Refusal refusal){throw refusal;}
            catch(Exception unavailable){
                // Best-effort diagnostics cannot mask the original fail-closed refusal.
                try{publicPolicyFailures.record(phase,unavailable,SystemClock.elapsedRealtime());}
                catch(Throwable diagnosticUnavailable){/* Original policy outcome is unchanged. */}
                if(publicNotesCustody!=null)publicNotesReadFailures.runtime(unavailable,SystemClock.elapsedRealtime());
                throw new BrokerProtocol.Refusal("PUBLIC_SCOPE_POLICY_UNAVAILABLE");
            }
        }
        KeyguardManager manager = keyguard;
        if (manager == null) throw new BrokerProtocol.Refusal("KEYGUARD_UNAVAILABLE");
        if (manager.isKeyguardLocked() || manager.isDeviceLocked()) throw new BrokerProtocol.Refusal("DEVICE_LOCKED");
        lastUnlockedCheck = SystemClock.elapsedRealtime();
    }

    private void verifyDisplay() throws Exception {
        long readStarted=SystemClock.elapsedRealtime();
        if (displayId <= 0) throw new BrokerProtocol.Refusal("DISPLAY_ID_INVALID");
        Display actual = displays.getDisplay(displayId);
        if (actual == null || !actual.isValid() || !displayName.equals(actual.getName()))
            throw new BrokerProtocol.Refusal("DISPLAY_IDENTITY_LOST");
        DisplayGeometry expected = displayGeometry;
        if (expected == null) throw new BrokerProtocol.Refusal("DISPLAY_GEOMETRY_NOT_SNAPSHOTTED");
        DisplayGeometry observed = DisplayGeometry.read(actual, displayId);
        boolean matches = expected.sameSize(observed);
        displayGeometryReadback = new JSONObject(observed.evidence()).put("schema", "hepta.background-display-geometry.v1")
            .put("source", "broker_framework_readback").put("generation", config.generation)
            .put("matches_snapshot", matches);
        if (!matches) throw new BrokerProtocol.Refusal("DISPLAY_GEOMETRY_CHANGED");
        int flags = actual.getFlags(); displayFlags = flags;
        if(config.publicOwnGroupScope!=null){
            publicOwnGroupLastReadback=publicOwnGroupFramework.read(config.generation,displayId,displayName);
            if("ACTIVE".equals(state))publicScreenLease.requireActive();
            publicOwnGroupDisplayReady=true;displayPolicyReadback=null;return;
        }
        if ((flags & requiredDisplayFlags) != requiredDisplayFlags || (flags & forbiddenDisplayFlags) != 0)
            throw new BrokerProtocol.Refusal("DISPLAY_FLAGS_NOT_ACCEPTED");
        Object policy = getImePolicy.invoke(windowManager, displayId);
        if (!(policy instanceof Integer) || ((Integer) policy).intValue() != imeHide)
            throw new BrokerProtocol.Refusal("IME_POLICY_NOT_ACCEPTED");
        BrokerProtocol.DisplayPolicy checked=BrokerProtocol.DisplayPolicy.checked(flags,displayFlagConstants,((Integer)policy).intValue(),imeHide);
        if(checked.requiredMask!=requiredDisplayFlags||checked.forbiddenMask!=forbiddenDisplayFlags)
            throw new BrokerProtocol.Refusal("DISPLAY_FLAG_CONSTANTS_INVALID");
        displayPolicyReadback=new JSONObject(checked.numericEvidence()).put("schema",BrokerProtocol.DisplayPolicy.SCHEMA)
            .put("source","broker_framework_readback").put("generation",config.generation)
            .put("display_id",displayId).put("display_name",displayName)
            .put("observed_started_elapsed_ms",readStarted).put("observed_ended_elapsed_ms",SystemClock.elapsedRealtime());
    }

    private void acquirePublicScreenLease(final VirtualDisplay created,long initializationDeadline)throws Exception{
        if(config.publicOwnGroupScope==null)return;
        if(created==null||created!=publicCreateReturnedHandle||created!=virtual||!publicOwnGroupDisplayReady
                ||publicOwnGroupLastReadback==null||!publicOwnGroupFramework.frozenIdentityMatches(displayId,displayName))
            throw new IOException("PUBLIC_SCREEN_CREATE_HANDLE_UNBOUND");
        final PublicOwnGroupPolicy.DisplayState bound=publicOwnGroupLastReadback.display;
        publicScreenLease.acquireInitiallyOn(new PublicOwnGroupScreenLease.Port(){
            private PowerManager.WakeLock token;
            @Override public PublicOwnGroupScreenLease.Snapshot read()throws Exception{
                if(created!=publicCreateReturnedHandle||created!=virtual||created.getDisplay().getDisplayId()!=displayId
                        ||closing.get()||publicAdmissionRetired.get())throw new IOException("PUBLIC_SCREEN_CREATE_HANDLE_RETIRED");
                PublicOwnGroupScreenLease.Snapshot actual=publicOwnGroupFramework.screenSnapshot(displayId,displayName);
                if(actual.id!=bound.displayId||!actual.name.equals(bound.name)||!actual.uniqueId.equals(bound.uniqueId)
                        ||actual.group!=bound.groupId||actual.ownerUid!=bound.ownerUid||!actual.ownerPackage.equals(bound.ownerPackage)
                        ||actual.flags!=bound.flags)throw new IOException("PUBLIC_SCREEN_FROZEN_IDENTITY_CHANGED");
                return actual;
            }
            @Override public void acquire(int flags,int selected,long remaining)throws Exception{
                if(flags!=0x0000000a||selected!=displayId||selected<=1||remaining<=0||remaining>BrokerProtocol.MAX_TTL_MS
                        ||closing.get()||publicAdmissionRetired.get())throw new IOException("PUBLIC_SCREEN_ACQUIRE_SCOPE_INVALID");
                Object value=newDisplayWakeLock.invoke(publicPowerManager,flags,"HeptaBackground:"+config.generation,selected);
                if(!(value instanceof PowerManager.WakeLock))throw new IOException("PUBLIC_SCREEN_WAKE_LOCK_UNAVAILABLE");
                token=(PowerManager.WakeLock)value;token.setReferenceCounted(false);
                // No ACQUIRE_CAUSES_WAKEUP or ON_AFTER_RELEASE: a newly created display must still be ON.
                token.acquire(remaining);
            }
            @Override public boolean held(){return token!=null&&token.isHeld();}
            @Override public void release(){if(token!=null&&token.isHeld())token.release();}
        },initializationDeadline,Thread::sleep);
    }
    private void retirePublicScreenLease(){if(publicScreenLease!=null)publicScreenLease.retire();}

    /** Logical maximum display region, not physical panel pixels or a foreground App window. */
    static final class DisplayGeometry {
        // Admission bounds; the existing screenshot path independently retains its 16M-pixel cap.
        static final int MAX_EDGE = 4096, MIN_DENSITY = 80, MAX_DENSITY = 1000;
        static final long MAX_PIXELS = 16000000L;
        final int displayId, width, height, density, rotation;
        final String name;
        final long startedElapsed, endedElapsed;
        private DisplayGeometry(int id, String name, int width, int height, int density, int rotation,
                                long started, long ended) {
            this.displayId=id;this.name=name;this.width=width;this.height=height;
            this.density=density;this.rotation=rotation;this.startedElapsed=started;this.endedElapsed=ended;
        }
        static DisplayGeometry snapshotDefault(DisplayManager manager) throws BrokerProtocol.Refusal {
            if (manager == null) throw new BrokerProtocol.Refusal("DISPLAY_GEOMETRY_UNAVAILABLE");
            // Never choose the first enumerated display: a foldable's cover display is a different ID.
            DisplayGeometry first=read(manager.getDisplay(Display.DEFAULT_DISPLAY),Display.DEFAULT_DISPLAY);
            DisplayGeometry second=read(manager.getDisplay(Display.DEFAULT_DISPLAY),Display.DEFAULT_DISPLAY);
            if (!first.sameSize(second) || first.rotation!=second.rotation || !first.name.equals(second.name)
                || second.startedElapsed<first.endedElapsed)
                throw new BrokerProtocol.Refusal("DEFAULT_DISPLAY_GEOMETRY_CHANGED");
            return new DisplayGeometry(second.displayId,second.name,second.width,second.height,second.density,
                second.rotation,first.startedElapsed,second.endedElapsed);
        }
        @SuppressWarnings("deprecation")
        static DisplayGeometry read(Display actual, int expectedId) throws BrokerProtocol.Refusal {
            long started=SystemClock.elapsedRealtime();
            if (expectedId<0 || actual==null || !actual.isValid() || actual.getDisplayId()!=expectedId)
                throw new BrokerProtocol.Refusal("DISPLAY_GEOMETRY_UNAVAILABLE");
            String name=actual.getName();
            int rotation=actual.getRotation();
            DisplayMetrics metrics=new DisplayMetrics();
            // This non-Activity broker sizes a new display. getRealMetrics preserves the current
            // logical/max-bounds region, rotation and wm overrides; no Display.Mode fallback.
            actual.getRealMetrics(metrics);
            if (!actual.isValid() || actual.getDisplayId()!=expectedId || name==null || name.isEmpty()
                || name.length()>256 || !name.equals(actual.getName()) || rotation!=actual.getRotation())
                throw new BrokerProtocol.Refusal("DISPLAY_GEOMETRY_CHANGED_DURING_READ");
            int width=metrics.widthPixels,height=metrics.heightPixels,density=metrics.densityDpi;
            long ended=SystemClock.elapsedRealtime();
            if (width<1 || height<1 || width>MAX_EDGE || height>MAX_EDGE || (long)width*height>MAX_PIXELS
                || density<MIN_DENSITY || density>MAX_DENSITY || rotation<0 || rotation>3
                || started<0 || ended<started)
                throw new BrokerProtocol.Refusal("DISPLAY_GEOMETRY_BOUNDS");
            return new DisplayGeometry(expectedId,name,width,height,density,rotation,started,ended);
        }
        boolean sameSize(DisplayGeometry other) {
            return other!=null && width==other.width && height==other.height && density==other.density;
        }
        java.util.Map<String,Object> evidence() {
            java.util.Map<String,Object> out=new java.util.LinkedHashMap<String,Object>();
            out.put("metrics_source","android.view.Display.getRealMetrics");out.put("display_id",displayId);
            out.put("display_name",name);out.put("width",width);out.put("height",height);out.put("density",density);
            out.put("rotation",rotation);out.put("pixels",(long)width*height);out.put("max_pixels",MAX_PIXELS);
            out.put("observed_started_elapsed_ms",startedElapsed);out.put("observed_ended_elapsed_ms",endedElapsed);
            return out;
        }
    }

    private void ensureNameAbsent() throws BrokerProtocol.Refusal {
        for (Display d : displays.getDisplays()) if (displayName.equals(d.getName()))
            throw new BrokerProtocol.Refusal("GENERATION_DISPLAY_ALREADY_EXISTS");
    }

    private void verifyLaunchedLocations(TaskSnapshot s) throws BrokerProtocol.Refusal {
        for (String pkg : launched) s.requireNoOtherDisplay(pkg, displayId);
    }

    /** Read the actual exported component twice; a missing mode is never substituted with zero. */
    private BackgroundOwnedTaskPolicy.Activity launchActivityInfo(ComponentName component, String pkg,
                                                                  int expectedUid) throws Exception {
        if (component == null || !pkg.equals(component.getPackageName()))
            throw new BrokerProtocol.Refusal("LAUNCH_ACTIVITY_COMPONENT_CHANGED");
        ActivityInfo info = shell.getPackageManager().getActivityInfo(component, 0);
        if (info == null || info.applicationInfo == null || !pkg.equals(info.packageName)
            || !pkg.equals(info.applicationInfo.packageName)
            || !component.equals(new ComponentName(info.packageName, info.name))
            || (expectedUid >= 0 && info.applicationInfo.uid != expectedUid))
            throw new BrokerProtocol.Refusal("LAUNCH_ACTIVITY_IDENTITY_CHANGED");
        try {
            return new BackgroundOwnedTaskPolicy.Activity(info.packageName, component.flattenToString(),
                info.applicationInfo.uid, info.launchMode, info.documentLaunchMode, info.flags,
                info.enabled, info.applicationInfo.enabled, info.exported, info.targetActivity,
                info.permission, info.applicationInfo.sourceDir);
        } catch (IllegalArgumentException invalid) {
            throw new BrokerProtocol.Refusal("LAUNCH_ACTIVITY_IDENTITY_INVALID");
        }
    }

    /**
     * RootTaskInfo exposes task names plus top/base activities, not every buried activity.
     * A missing package in that metadata cannot authorize a framework task-reuse mode.
     * Keep only the supported standard/NONE fresh-task path; never migrate or clear a user task.
     */
    private static void requireIsolatedTaskLaunch(BackgroundOwnedTaskPolicy.Plan plan)
            throws BrokerProtocol.Refusal {
        if (plan == null || !plan.eligible)
            throw new BrokerProtocol.Refusal("BACKGROUND_LAUNCH_CAPABILITY_UNAVAILABLE");
    }

    private JSONObject taskLaunchPolicyEvidence(BrokerProtocol.Request request,
            BackgroundOwnedTaskPolicy.Activity activity, BackgroundOwnedTaskPolicy.Plan plan) throws Exception {
        return new JSONObject().put("schema",BackgroundOwnedTaskPolicy.SCHEMA)
            .put("request_id",request.requestId).put("generation",plan.generation)
            .put("display_id",plan.displayId).put("package",plan.packageName)
            .put("component",plan.component).put("target_uid",plan.targetUid)
            .put("activity_info_source","PackageManager.getActivityInfo")
            .put("activity_info_rechecked_before_dispatch",true)
            .put("actual_launch_mode",plan.launchMode).put("actual_document_launch_mode",plan.documentLaunchMode)
            .put("actual_activity_info_flags",plan.manifestFlags)
            .put("actual_activity_enabled",activity.enabled).put("actual_application_enabled",activity.applicationEnabled)
            .put("actual_exported",activity.exported)
            .put("actual_target_activity",activity.targetActivity==null?JSONObject.NULL:activity.targetActivity)
            .put("actual_required_permission",activity.permission==null?JSONObject.NULL:activity.permission)
            .put("actual_source_dir",activity.sourceDir)
            .put("original_intent_flags",plan.originalFlags).put("outbound_intent_flags",plan.outboundFlags)
            .put("policy_eligible",plan.eligible).put("policy_reason",plan.reason)
            .put("new_document_requested",plan.newDocumentRequested)
            .put("retain_in_recents_requested",(plan.outboundFlags&BackgroundOwnedTaskPolicy.RETAIN_IN_RECENTS)!=0)
            .put("framework_adjusted_flags_verified",plan.frameworkFlagsVerified)
            .put("new_owned_task_identity_verified",plan.taskOwnershipVerified)
            .put("recents_cleanup_verified",plan.recentsCleanupVerified)
            .put("scope","Outbound new-task Intent only; no task removal or global policy change; not a cleanup proof.");
    }

    /** Requires the privileged whole-root list, not a per-application filtered getRunningTasks view. */
    private TaskSnapshot snapshot() throws Exception {
        Object raw = allRootTasks.invoke(activityTasks);
        if (!(raw instanceof List)) throw new BrokerProtocol.Refusal("TASK_SNAPSHOT_UNAVAILABLE");
        List<?> roots = (List<?>) raw;
        if (roots.isEmpty() || roots.size() > 256) throw new BrokerProtocol.Refusal("TASK_SNAPSHOT_BOUNDS");
        List<TaskRow> rows = new ArrayList<TaskRow>(); int childrenCount = 0;
        for (Object root : roots) {
            if (root == null) throw new BrokerProtocol.Refusal("TASK_SNAPSHOT_INCOMPLETE");
            Class<?> type = root.getClass();
            int id = type.getField("displayId").getInt(root);
            boolean visible = type.getField("visible").getBoolean(root);
            int activities = type.getField("numActivities").getInt(root);
            if (activities < 0 || activities > 2048)
                throw new BrokerProtocol.Refusal("TASK_SNAPSHOT_BOUNDS");
            Set<String> packages = new LinkedHashSet<String>();
            ComponentName top = component(type.getField("topActivity").get(root));
            ComponentName base = component(type.getField("baseActivity").get(root));
            if (top != null) packages.add(top.getPackageName());
            if (base != null) packages.add(base.getPackageName());
            Object childIds = type.getField("childTaskIds").get(root);
            Object childNames = type.getField("childTaskNames").get(root);
            if (!(childIds instanceof int[]) || !(childNames instanceof String[])
                || ((int[]) childIds).length != ((String[]) childNames).length)
                throw new BrokerProtocol.Refusal("TASK_SNAPSHOT_INCOMPLETE");
            String[] names = (String[]) childNames; childrenCount += names.length;
            if (id < 0 || childrenCount > 2048) throw new BrokerProtocol.Refusal("TASK_SNAPSHOT_BOUNDS");
            // Root TaskInfo counts non-finishing descendant activities. Empty organizer containers have
            // literal "unknown" child names; admission requires all independent fields here.
            boolean emptyContainer = activities == 0 && !visible && top == null && base == null;
            boolean ownedAnchorSeen=false;
            for (int childIndex=0;childIndex<names.length;childIndex++) {
                String name=names[childIndex];
                ComponentName child = name == null ? null : ComponentName.unflattenFromString(name);
                if (child != null) packages.add(child.getPackageName());
                else if (BrokerProtocol.packageName(name)) packages.add(name);
                else if (emptyContainer && "unknown".equals(name)) { /* Empty task metadata; never ignore a resolved app package. */ }
                else if ("unknown".equals(name) && !ownedAnchorSeen && ownedSingleTask!=null
                    && ownedSingleTask.provesEmptyAnchor(id,type.getField("taskId").getInt(root),((int[])childIds)[childIndex])) {
                    /* Only the new generation's fresh empty anchor; all other unresolved children still reject. */
                    ownedAnchorSeen=true;
                }
                else throw new BrokerProtocol.Refusal("TASK_COMPONENT_UNRESOLVED");
            }
            rows.add(new TaskRow(id, visible, top == null ? null : top.getPackageName(), packages));
        }
        return new TaskSnapshot(rows);
    }

    private static ComponentName component(Object value) throws BrokerProtocol.Refusal {
        if (value == null || value instanceof ComponentName) return (ComponentName) value;
        throw new BrokerProtocol.Refusal("TASK_COMPONENT_UNRESOLVED");
    }
    private static final class TaskRow {
        final int display; final boolean visible; final String top; final Set<String> packages;
        TaskRow(int display, boolean visible, String top, Set<String> packages) {
            this.display = display; this.visible = visible; this.top = top; this.packages = packages;
        }
    }
    private static final class TaskSnapshot {
        final List<TaskRow> rows;
        TaskSnapshot(List<TaskRow> rows) { this.rows = rows; }
        void requireNoOtherDisplay(String pkg, int display) throws BrokerProtocol.Refusal {
            for (TaskRow row : rows) if (row.display != display && row.packages.contains(pkg))
                throw new BrokerProtocol.Refusal(row.display == 0 ? "APP_ALREADY_ON_MAIN_DISPLAY" : "APP_ALREADY_ON_OTHER_DISPLAY");
        }
        String singleVisibleTop(int display) throws BrokerProtocol.Refusal {
            String result = null;
            for (TaskRow row : rows) if (row.display == display && row.visible && row.top != null) {
                if (result != null && !result.equals(row.top)) throw new BrokerProtocol.Refusal("AMBIGUOUS_TARGET_WINDOW");
                result = row.top;
            }
            return result;
        }
    }

    private void startWatchdog() {
        Thread watchdog = new Thread(() -> {
            while (true) {
                long now = SystemClock.elapsedRealtime();
                // PowerManager's timeout posts to the unpumped main Looper in this app_process.
                // This independent watchdog is the authoritative absolute screen-lease deadline.
                if(publicScreenLease!=null)publicScreenLease.observeDeadline(now);
                if(config.publicOwnGroupScope!=null)publicSurfaceRetirement.observeDeadline(now);
                if (cleanupStarted.get() && now - cleanupAt >= CLEANUP_MS && !releasedProfileReplyMayFlush(now)) {
                    boolean known = cleanupDone.getCount() == 0 && "RELEASED".equals(state);
                    if(config.profileTarget!=null&&profileCustody.known()){
                        state=releasedState();haltAfterBootRead(0);
                    }
                    if(config.profileTarget!=null&&profileCustody.retain()){
                        quarantineProfile("cleanup_deadline");printTerminal();retainedWatchdogHoldPublished=true;return;
                    }
                    if(publicNotesCustody!=null&&publicNotesCustody.known()){
                        state=releasedState();haltAfterBootRead(0);
                    }
                    if(publicNotesCustody!=null&&publicNotesCustody.retain()){
                        quarantinePublicNotes("NOTES_CLEANUP_DEADLINE");printTerminal();return;
                    }
                    if (!known) state = "CLEANUP_UNKNOWN";
                    // Bound even a stalled cleanup or a client that stops reading the close response.
                    // Process death without confirmed absence is never labeled RELEASED.
                    haltAfterBootRead(known ? 0 : 70);
                }
                if (!closing.get()) {
                    if (now >= expires) shutdown("SESSION_EXPIRED");
                    else if (!frameworkReady && now - started >= STARTUP_MS) shutdown("FRAMEWORK_STARTUP_DEADLINE");
                    else if (frameworkReady && now - lastUnlockedCheck > 1500) shutdown("KEYGUARD_MONITOR_STALLED");
                    else if (requestDeadline != 0 && now >= requestDeadline) shutdown("REQUEST_DEADLINE");
                    else if (connectionDeadline != 0 && now >= connectionDeadline) {
                        // An unauthenticated slow peer may lose its own socket, but cannot retire a session.
                        if (requestDeadline != 0) shutdown("REQUEST_DEADLINE");
                        else { LocalSocket peer = connection; if (peer != null) try { peer.close(); } catch (IOException ignored) {} }
                    }
                }
                try { Thread.sleep(50); } catch (InterruptedException ignored) { /* Not a cancellation bypass. */ }
            }
        }, "HeptaBackgroundDeadline");
        watchdog.setDaemon(true); watchdog.start();
    }

    private boolean profileCloseReplyPending(long now){
        LocalSocket peer=authenticatedProfileClosePeer;
        return peer!=null&&peer==connection&&closing.get()&&now<requestDeadline;
    }
    private boolean releasedProfileReplyMayFlush(long now){
        // The cleanup deadline and unknown-custody watchdog are unchanged. Only a
        // verified release may finish its reply on the original socket, within both
        // the original request deadline and a short independent write bound.
        return profileCloseReplyPending(now)&&cleanupDone.getCount()==0&&"RELEASED".equals(state)
                &&profileCustody.known()&&now>=cleanupAt&&now-cleanupAt<CLEANUP_MS+750;
    }

    private void shutdown(String reason) {
        serve = false; beginCleanup(reason); closeSockets();
    }

    private void retireBootRead() {
        try { publicBootCount.abortForDeadline(); }
        catch(Throwable failure) { bootReadRetirementFailure=failure.getClass().getName(); }
    }

    private String releasedState() {
        WindowInfosCapture capture=calendarWindowCapture;
        return bootReadRetirementFailure==null&&(capture==null||capture.locallyDrained())?"RELEASED":"CLEANUP_UNKNOWN";
    }

    private void haltAfterBootRead(int exit) {
        try {
            retirePublicScreenLease();
            retireBootRead();
            if(bootReadRetirementFailure!=null)state="CLEANUP_UNKNOWN";
            printTerminal();
        }
        finally { Runtime.getRuntime().halt(bootReadRetirementFailure==null?exit:70); }
    }

    private void beginCleanup(String reason) {
        closing.set(true);
        WindowInfosCapture inputCapture=calendarWindowCapture;if(inputCapture!=null)inputCapture.retire();
        retirePublicScreenLease();
        retireBootRead();
        if(publicNotesCustody!=null)publicNotesCustody.retireAdmission();
        if(config.publicOwnGroupScope!=null){publicAdmissionRetired.set(true);beginPublicSurfaceDetach();}
        if (!cleanupStarted.compareAndSet(false, true)) return;
        cleanupAt = SystemClock.elapsedRealtime(); terminalReason = reason; state = "CLOSING";
        if(config.profileTarget!=null){beginProfileCleanup();return;}
        if(publicNotesCustody!=null){beginPublicNotesCleanup();return;}
        Thread cleanup = new Thread(() -> {
            boolean releaseCallFailed = false;
            try {
                // Mutating calls and release share one gate. If a Binder call stalls while holding it,
                // the independent watchdog records UNKNOWN and terminates the owning process.
                synchronized (dispatchGate) {
                    BackgroundOwnedSingleTask ownedTasks=ownedSingleTask;
                    if(ownedTasks!=null)try { ownedTasks.retire(); } catch(Throwable error) { releaseCallFailed=true; }
                    VirtualDisplay owned = virtual;
                    if (owned != null) try { owned.release(); } catch (Throwable error) { releaseCallFailed = true; }
                    ImageReader reader = surfaceReader;
                    if (reader != null) try { reader.close(); } catch (Throwable error) { releaseCallFailed = true; }
                    HandlerThread worker = displayThread;
                    if (worker != null) worker.quitSafely();
                }
                if (createInFlight || effectInFlight) { state = "CLEANUP_UNKNOWN"; return; }
                boolean gone = false;
                while (SystemClock.elapsedRealtime() - cleanupAt < CLEANUP_MS - 100) {
                    DisplayManager dm = displays;
                    if (dm == null) { gone = virtual == null && !createInFlight && !effectInFlight; break; }
                    boolean present = displayId > 0 && dm.getDisplay(displayId) != null;
                    for (Display d : dm.getDisplays()) if (displayName.equals(d.getName())) present = true;
                    if (!present && (ownedSingleTask==null || ownedSingleTask.absent())) { gone = true; break; }
                    Thread.sleep(25);
                }
                // A release exception can still end in proven absence; the actual absence is decisive.
                state = gone && !createInFlight && !effectInFlight ? releasedState() : "CLEANUP_UNKNOWN";
                if (releaseCallFailed && !gone) terminalReason += ":release_api_failed";
            } catch (Throwable error) { state = "CLEANUP_UNKNOWN"; }
            finally { cleanupDone.countDown(); }
        }, "HeptaBackgroundCleanup");
        cleanup.setDaemon(true); cleanup.start();
    }

    private void beginPublicSurfaceDetach(){
        if(config.publicOwnGroupScope==null||!publicAdmissionRetired.get()||!closing.get())return;
        if(!publicSurfaceRetirement.request(SystemClock.elapsedRealtime()))return;
        startPublicSurfaceDetach(null);
    }
    private void startPublicSurfaceDetach(final VirtualDisplay lateCreated){
        if(config.publicOwnGroupScope==null||!publicAdmissionRetired.get()||!closing.get()||!publicSurfaceRetirement.retired())return;
        try{
        PublicOwnGroupSurfaceRetirement.OwnedSurface operation=new PublicOwnGroupSurfaceRetirement.OwnedSurface(){
            private VirtualDisplay exact;
            @Override public String prepare()throws Exception{
                // A create call can still be returning. Wait only for that actual in-memory handle;
                // expiry/stall keeps UNKNOWN and never invents authority from the display number.
                long until=publicSurfaceRetirement.deadlineElapsed();
                while(lateCreated==null&&publicCreateReturnedHandle==null&&createInFlight&&SystemClock.elapsedRealtime()<until)Thread.sleep(10);
                exact=lateCreated==null?publicCreateReturnedHandle:lateCreated;
                if(exact==null||exact!=virtual)throw new IOException("PUBLIC_OWNED_SURFACE_HANDLE_UNAVAILABLE");
                if(lateCreated!=null){
                    if(exact!=publicCreateReturnedHandle)throw new IOException("PUBLIC_CREATE_RETURNED_HANDLE_CHANGED");
                    return "CREATE_RETURNED_HANDLE_ONLY";
                }
                PublicOwnGroupFramework framework=publicOwnGroupFramework;
                if(framework!=null&&framework.hasFrozenIdentity()){
                    if(!framework.frozenIdentityMatches(displayId,displayName))throw new IOException("PUBLIC_FROZEN_SURFACE_IDENTITY_CHANGED");
                    return "FROZEN_FRAMEWORK_IDENTITY";
                }
                // Initializing has never admitted input/model work. The real returned Binder-owning
                // object is sufficient only for requesting this surface's shutdown, never for activation.
                return "CREATE_RETURNED_HANDLE_ONLY";
            }
            @Override public void detach(PublicOwnGroupSurfaceRetirement.ApiEntry entry)throws Exception{
                if(!publicAdmissionRetired.get()||!closing.get()||exact==null||exact!=publicCreateReturnedHandle||exact!=virtual)
                    throw new IOException("PUBLIC_OWNED_SURFACE_HANDLE_CHANGED");
                entry.beforeCall();
                exact.setSurface(null);
            }
        };
        Thread worker=new Thread(()->{
            if(lateCreated==null)publicSurfaceRetirement.run(operation,SystemClock::elapsedRealtime);
            else publicSurfaceRetirement.runLateCreated(operation,SystemClock::elapsedRealtime);
        },"HeptaPublicOwnedSurfaceDetach");
        worker.setDaemon(true);worker.start();
        }catch(Throwable unavailable){publicSurfaceRetirement.workerUnavailable(unavailable,SystemClock.elapsedRealtime());}
    }
    private JSONObject publicDetachEvidence(){return new JSONObject(publicSurfaceRetirement.evidence());}

    private void beginPublicNotesCleanup(){
        try{
        Thread cleanup=new Thread(()->{
            try{
                PublicPersonalNotesCustody custody=publicNotesCustody;
                PublicPersonalNotesRetirementAdapter retirementAdapter;
                PublicPersonalNotesRetirement retirement;
                synchronized(dispatchGate){
                    if(!custody.createAttempted()){
                        if(virtual!=null||createInFlight||effectInFlight)throw new IOException("NOTES_CREATE_STATE_UNKNOWN");
                        custody.notCreated();state=releasedState();return;
                    }
                    PublicPersonalNotesReader reader=publicNotesReader;
                    if(reader==null||virtual==null||virtual!=publicCreateReturnedHandle||createInFlight||effectInFlight)
                        throw new IOException("NOTES_OWNED_DISPLAY_OR_READER_UNKNOWN");
                    long originalDeadline=cleanupAt+CLEANUP_MS-100;
                    retirementAdapter=new PublicPersonalNotesRetirementAdapter(shell,activityTasks,windowManager,displays,
                            reader,publicOwnGroupFramework,displayId,displayName,custody.expectedUid(),originalDeadline,()->{
                        if(!closing.get()||!publicAdmissionRetired.get()||!cleanupStarted.get()||virtual==null
                                ||virtual!=publicCreateReturnedHandle||createInFlight||effectInFlight)
                            throw new IOException("NOTES_RETIRED_ORIGINAL_HANDLE_REQUIRED");
                    });
                    retirement=new PublicPersonalNotesRetirement(custody,retirementAdapter,originalDeadline);
                    retirement.retire();
                    // Only this session's actual create-returned VD handle is released.
                    // Original attached leaf tokens have two complete absences first.
                    // No detached recent, numerical task id or broad root is removed.
                    if(virtual!=publicCreateReturnedHandle)throw new IOException("NOTES_OWNED_DISPLAY_CHANGED");
                    retirement.beforeRelease(SystemClock.elapsedRealtime());
                    custody.enterRelease(SystemClock.elapsedRealtime());virtual.release();custody.releaseReturned();
                    ImageReader images=surfaceReader;if(images!=null)images.close();
                    HandlerThread worker=displayThread;if(worker!=null)worker.quitSafely();
                }
                long end=cleanupAt+CLEANUP_MS-100;
                while(SystemClock.elapsedRealtime()<end){
                    if(!publicOwnedDisplayAbsent()){Thread.sleep(25);continue;}
                    PublicPersonalNotesRetirement.Sample sample=retirementAdapter.readReleased(custody.releasedRead());
                    retirement.afterRelease(sample,SystemClock.elapsedRealtime());
                    custody.observeAbsence(sample.frame.global,sample.recents,null,publicOwnedDisplayAbsent(),
                            sample.begin,sample.end,SystemClock.elapsedRealtime());
                    if(custody.known()){state=releasedState();return;}
                    Thread.sleep(50);
                }
                throw new IOException("NOTES_CLEANUP_ABSENCE_DEADLINE");
            }catch(Throwable error){
                if(publicNotesCleanupFailure==null)publicNotesCleanupFailure=error;
                publicNotesReadFailures.cleanup(error,SystemClock.elapsedRealtime());quarantinePublicNotes(error.getMessage());
            }
            finally{cleanupDone.countDown();}
        },"HeptaPublicNotesCleanup");cleanup.setDaemon(true);cleanup.start();
        }catch(Throwable scheduling){quarantinePublicNotes("NOTES_CLEANUP_WORKER_UNAVAILABLE");cleanupDone.countDown();}
    }
    private boolean publicOwnedDisplayAbsent()throws Exception{
        return PublicPersonalNotesRetirementAdapter.displayAbsent(displayId,displayName);
    }
    private void quarantinePublicNotes(String reason){
        retirePublicScreenLease();
        PublicPersonalNotesCustody custody=publicNotesCustody;
        if(custody!=null&&!custody.known())custody.unresolved(reason);
        serve=false;state=custody!=null&&custody.known()?releasedState():"CLEANUP_UNKNOWN";
        if(terminalReason.isEmpty())terminalReason=reason==null?"NOTES_CLEANUP_UNKNOWN":reason;
        LocalServerSocket socket=server;if(socket!=null)try{socket.close();}catch(IOException ignored){}
    }
    private void holdPublicNotesCustody(){
        while(publicNotesCustody!=null&&publicNotesCustody.retain()){
            try{Thread.sleep(250);}catch(InterruptedException ignored){}
        }
    }

    private void beginProfileCleanup(){
        Thread cleanup=new Thread(()->{
            try{
                synchronized(dispatchGate){
                    ProfileOwnedTask tasks=profileOwnedTask;
                    if(tasks!=null){
                        profileCleanupFailures.phase(ProfileCleanupFailureAudit.Phase.TASK_RETIRE);
                        tasks.retire(cleanupAt+CLEANUP_MS-100);
                        refreshProfileTaskEvidence();
                        if(!tasks.cleanupKnown())throw new IOException("PROFILE_TASK_RETIRE_UNCONFIRMED");
                    }else{
                        profileCleanupFailures.phase(ProfileCleanupFailureAudit.Phase.UNLAUNCHED_PROFILE);
                        recheckProfile(false,cleanupAt+CLEANUP_MS-100);
                        requireUnlaunchedProfileEmpty();
                        profileCleanupReadback=emptyProfileCleanup(true);
                    }
                    profileCleanupFailures.phase(ProfileCleanupFailureAudit.Phase.DISPLAY_RELEASE);
                    profileCustody.tasksVerified();
                    // The watchdog can mark uncertainty while a Binder call is in flight. It is
                    // monotonic: an observed quarantine refuses a new release call. A release
                    // already in flight can still time out; its custodian then remains alive.
                    if(!profileCustody.mayRelease())throw new IOException("PROFILE_CUSTODY_QUARANTINED");
                    VirtualDisplay owned=virtual;
                    if(owned!=null){profileDisplayReleaseAttempted=true;owned.release();}
                    ImageReader reader=surfaceReader;if(reader!=null)reader.close();
                    HandlerThread worker=displayThread;if(worker!=null)worker.quitSafely();
                }
                profileCleanupFailures.phase(ProfileCleanupFailureAudit.Phase.DISPLAY_ABSENCE);
                if(createInFlight||effectInFlight)throw new IOException("PROFILE_EFFECT_UNRESOLVED");
                boolean gone=false;
                while(SystemClock.elapsedRealtime()<cleanupAt+CLEANUP_MS-100){
                    DisplayManager dm=displays;
                    if(dm==null){gone=virtual==null&&!createInFlight&&!effectInFlight;break;}
                    boolean present=displayId>0&&dm.getDisplay(displayId)!=null;
                    for(Display display:dm.getDisplays())if(displayName.equals(display.getName()))present=true;
                    if(!present){gone=true;break;}
                    Thread.sleep(25);
                }
                if(!gone)throw new IOException("PROFILE_DISPLAY_ABSENCE_UNCONFIRMED");
                if(publicProfileHistory!=null){
                    profileCleanupFailures.phase(ProfileCleanupFailureAudit.Phase.FINAL_PROFILE_IDENTITY);
                    recheckProfile(false,cleanupAt+CLEANUP_MS-100);
                    profileCleanupFailures.phase(ProfileCleanupFailureAudit.Phase.FINAL_GLOBAL_TASKS);
                    BackgroundTaskOrganizer.profileSnapshot(activityTasks).requireDedicatedEmpty(config.profileTarget);
                    profileCleanupFailures.phase(ProfileCleanupFailureAudit.Phase.FINAL_PUBLIC_RECENTS);
                    publicProfileHistory.requireTargetAbsent(BackgroundTaskOrganizer.profileRecents(()->cleanupAt+CLEANUP_MS-100),
                            config.profileTarget,SystemClock.elapsedRealtime());
                }
                profileCustody.displayVerifiedAbsent();state=releasedState();
            }catch(Throwable error){
                // Never release, close the surface, halt, or exit merely because retire failed.
                if(profileOwnedTask!=null)refreshProfileTaskEvidence();
                quarantineProfile(code(error));
            }finally{cleanupDone.countDown();}
        },"HeptaProfileCleanup");
        cleanup.setDaemon(true);cleanup.start();
    }
    private void refreshProfileTaskEvidence(){
        ProfileOwnedTask tasks=profileOwnedTask;
        if(tasks!=null){profileCleanupReadback=tasks.cleanupEvidence();profilePersonalAudit=tasks.personalAudit();}
    }
    private java.util.Map<String,Object> emptyProfileCleanup(boolean known){
        ProfileTarget target=config.profileTarget;
        java.util.Map<String,Object> out=new java.util.LinkedHashMap<String,Object>();
        out.put("schema","hepta.profile-task-cleanup.v1");out.put("generation",config.generation);
        out.put("display_id",displayId);out.put("target_sha256",target.sha256);
        out.put("user_id",target.profile.userId);out.put("user_serial",target.profile.serial);out.put("full_uid",target.fullUid);
        out.put("cleanup_known",known);out.put("live_tasks_absent",known);out.put("recents_tasks_absent",known);
        out.put("foreign_tasks_present",false);out.put("identity_unknown",!known);
        out.put("owned_tasks",java.util.Collections.emptyList());
        if(publicProfileHistory!=null){out.put("public_foreign_recent_history",publicProfileHistory.evidence());
            out.put("recents_absence_scope","owned_target_only_with_foreign_history_preserved");}
        return java.util.Collections.unmodifiableMap(out);
    }
    private void quarantineProfile(String reason){
        // Keep the first cleanup refusal separate from the original close/Stop reason.
        // Diagnostics never change custody, deadlines, or the cleanup outcome.
        try{profileCleanupFailures.record(reason,cleanupAt,cleanupAt+CLEANUP_MS-100,SystemClock.elapsedRealtime());}
        catch(Throwable unavailable){/* Original quarantine remains authoritative. */}
        retirePublicScreenLease();
        profileCustody.unresolved();serve=false;state="CLEANUP_UNKNOWN";
        java.util.Map<String,Object> previous=profileCleanupReadback;
        java.util.Map<String,Object> out=new java.util.LinkedHashMap<String,Object>(
                previous==null?emptyProfileCleanup(false):previous);
        out.put("cleanup_known",false);out.put("live_tasks_absent",false);out.put("recents_tasks_absent",false);
        out.put("identity_unknown",true);profileCleanupReadback=java.util.Collections.unmodifiableMap(out);
        if(terminalReason.isEmpty())terminalReason=reason;
        LocalServerSocket listening=server;
        if(listening!=null)try{listening.close();}catch(IOException ignored){}
    }
    private final AtomicBoolean retainedRecheckStarted=new AtomicBoolean();
    private final ThreadLocal<Long> retainedReadDeadline=new ThreadLocal<Long>();
    private volatile boolean profileDisplayReleaseAttempted,retainedWatchdogHoldPublished;
    private volatile String retainedRecheckOutcome="";
    private void recheckRetainedEmptyDisplay(){
        if(config.publicOwnGroupScope==null||publicProfileHistory==null||!publicAdmissionRetired.get()
                ||!closing.get()||serve||createInFlight||effectInFlight||cleanupDone.getCount()!=0||!retainedWatchdogHoldPublished
                ||profileDisplayReleaseAttempted||!publicSurfaceRetirement.originalDetachCompleted()
                ||!retainedRecheckStarted.compareAndSet(false,true))return;
        if(!capturedRetainedSnapshot()){retainedRecheckOutcome="ORIGINAL_SNAPSHOT_ACK_UNAVAILABLE";return;}
        final long deadline=SystemClock.elapsedRealtime()+10000;
        retainedReadDeadline.set(deadline);
        try{
            synchronized(dispatchGate){
                final ProfileOwnedTask tasks=profileOwnedTask;final VirtualDisplay exact=virtual;
                if(tasks==null||exact==null||exact!=publicCreateReturnedHandle||profileDisplayReleaseAttempted
                        ||createInFlight||effectInFlight||!publicOwnGroupFramework.hasFrozenIdentity())
                    throw new IOException("PROFILE_RETAINED_ORIGINAL_HANDLE_MISSING");
                tasks.closeRetainedEmptyDisplay(deadline,new ProfileOwnedTask.RetiredDisplay(){
                    private PublicProfileRecentHistory.Snapshot first;
                    private long initial;
                    public void requireState(boolean before)throws Exception{
                        if(SystemClock.elapsedRealtime()>=deadline||exact!=virtual||exact!=publicCreateReturnedHandle)
                            throw new IOException("PROFILE_RETAINED_ORIGINAL_HANDLE_CHANGED");
                        if(before)publicOwnGroupFramework.requireRetiredDestroyHandle(displayId,displayName);
                        else if(!publicOwnedDisplayAbsent())throw new IOException("PROFILE_RETAINED_DISPLAY_STILL_PRESENT");
                        String raw=BackgroundTaskOrganizer.profileRecents(()->deadline);
                        long now=SystemClock.elapsedRealtime();PublicProfileRecentHistory.Snapshot actual=PublicProfileRecentHistory.absence(raw,config.profileTarget);
                        if(first==null){first=actual;initial=now;}else first.requireSame(actual,(now-initial)/1000+2);
                    }
                    public void awaitAbsent()throws Exception{
                        while(!publicOwnedDisplayAbsent()){
                            if(SystemClock.elapsedRealtime()>=deadline)throw new IOException("PROFILE_RETAINED_DISPLAY_STILL_PRESENT");
                            Thread.sleep(25);
                        }
                    }
                    public void releaseOriginalHandle()throws Exception{
                        if(profileDisplayReleaseAttempted||exact!=virtual||exact!=publicCreateReturnedHandle
                                ||createInFlight||effectInFlight||SystemClock.elapsedRealtime()>=deadline)
                            throw new IOException("PROFILE_RETAINED_RELEASE_ALREADY_ATTEMPTED");
                        profileDisplayReleaseAttempted=true;exact.release();
                        if(surfaceReader!=null)surfaceReader.close();
                        if(displayThread!=null)displayThread.quitSafely();
                    }
                });
                profileCustody.retainedObservedAbsent(tasks);refreshProfileTaskEvidence();
                retainedRecheckOutcome="RELEASED_AFTER_ORIGINAL_UNKNOWN";state=releasedState();printTerminal();
            }
        }catch(Throwable refusal){retainedRecheckOutcome=code(refusal);}
        finally{retainedReadDeadline.remove();}
    }
    private boolean capturedRetainedSnapshot(){
        byte[] expected=PublicOwnGroupPolicy.retainedSnapshotAcknowledgement(config.publicOwnGroupScope);
        byte[] actual=new byte[expected.length];long until=SystemClock.elapsedRealtime()+6000;
        try{
            // One reader, bounded wait, the original ProcessBuilder pipe only. No socket
            // is reopened and neither a serialized task id nor the pipe grants ownership.
            while(SystemClock.elapsedRealtime()<until){
                int count=System.in.available();if(count>actual.length)return false;
                if(count==actual.length){
                    new java.io.DataInputStream(System.in).readFully(actual);
                    return SystemClock.elapsedRealtime()<until&&java.util.Arrays.equals(expected,actual);
                }
                Thread.sleep(20);
            }
        }catch(Exception unavailable){return false;}
        return false;
    }
    private void holdProfileCustody(){
        // Retaining the live binder owner is intentional. DESTROY_CONTENT_ON_REMOVAL remains
        // enabled; removing that flag would allow main-display migration instead. Unexpected
        // SIGKILL, OS process death or power loss is still UNKNOWN, never a cleanup proof.
        while(config.profileTarget!=null&&profileCustody.retain()){
            if(config.retainedCleanupTokenSha256==null)recheckRetainedEmptyDisplay();
            else startRetainedCleanupServer();
            try{Thread.sleep(250);}catch(InterruptedException ignored){}
        }
    }
    /** A distinct retired-state endpoint. It never sets serve, clears closing,
     * reopens the business socket, resets expiry, or prints another old terminal. */
    private void startRetainedCleanupServer(){
        if(config.retainedCleanupTokenSha256==null||config.publicOwnGroupScope==null||config.profileTarget==null
                ||!publicAdmissionRetired.get()||!closing.get()||serve||createInFlight||effectInFlight
                ||cleanupDone.getCount()!=0||!retainedWatchdogHoldPublished||profileDisplayReleaseAttempted
                ||!publicSurfaceRetirement.originalDetachCompleted()||!profileCustody.retain()
                ||!retainedCleanupServerStarted.compareAndSet(false,true))return;
        Thread thread=new Thread(()->{
            try(LocalServerSocket cleanupServer=new LocalServerSocket(BrokerProtocol.retainedCleanupSocket(config.generation))){
                while(profileCustody.retain()&&!retainedCleanupAttempt.claimed()){
                    LocalSocket accepted=cleanupServer.accept();
                    try(LocalSocket peer=accepted){
                        android.net.Credentials credentials=peer.getPeerCredentials();
                        if(credentials==null||credentials.getUid()!=config.ownerUid)continue;
                        peer.setSoTimeout((int)SOCKET_MS);
                        BrokerProtocol.RetainedCleanupRequest request;
                        try{
                            request=BrokerProtocol.RetainedCleanupRequest.parse(BrokerProtocol.readFrame(peer.getInputStream()));
                            retainedCleanupAttempt.claim(request,credentials.getUid());
                        }catch(Exception invalid){continue;}
                        final LocalSocket exactPeer=peer;final long deadline=request.deadline;final AtomicBoolean replyDone=new AtomicBoolean();
                        Thread closer=new Thread(()->{
                            while(SystemClock.elapsedRealtime()<deadline&&!replyDone.get()){
                                try{Thread.sleep(Math.min(50,Math.max(1,deadline-SystemClock.elapsedRealtime())));}
                                catch(InterruptedException ignored){}
                            }
                            if(!replyDone.get())try{exactPeer.close();}catch(IOException ignored){}
                        },"HeptaRetainedCleanupReplyDeadline");closer.setDaemon(true);closer.start();
                        ProfileOwnedTask original=profileOwnedTask;
                        try{
                            retainedCleanupAttempt.run(this::cleanupRetainedProfile);
                        }catch(Throwable refused){/* The independent reply records failure. No second attempt. */}
                        try{
                            long remaining=deadline-SystemClock.elapsedRealtime();
                            if(remaining<=0)throw new IOException("RETAINED_CLEANUP_REPLY_DEADLINE");
                            peer.setSoTimeout((int)Math.min(SOCKET_MS,remaining));
                            BrokerProtocol.writeFrame(peer.getOutputStream(),new JSONObject(retainedCleanupAttempt.evidence())
                                    .toString().getBytes(StandardCharsets.UTF_8));
                        }finally{
                            // Flush/close precedes custody exit, so main's original
                            // exit(70) cannot kill an otherwise complete reply.
                            try{peer.close();}catch(IOException ignored){}
                            replyDone.set(true);
                            ProfileOwnedTask.RetainedCleanupProof proof=retainedCleanupAttempt.completedProof();
                            if(proof!=null)profileCustody.retainedCleanupObservedAbsent(original,proof);
                        }
                    }catch(Exception refused){/* Keep the original unknown state and original handles. */}
                }
            }catch(Exception unavailable){/* No fallback socket, no loss of live custody. */}
        },"HeptaRetainedCleanupOnly");thread.setDaemon(true);thread.start();
    }
    private ProfileOwnedTask.RetainedCleanupProof cleanupRetainedProfile(final long deadline)throws Exception{
        retainedReadDeadline.set(deadline);
        try{
            synchronized(dispatchGate){
                final ProfileOwnedTask original=profileOwnedTask;final VirtualDisplay exact=virtual;
                if(!publicAdmissionRetired.get()||!closing.get()||serve||createInFlight||effectInFlight
                        ||cleanupDone.getCount()!=0||!retainedWatchdogHoldPublished||!profileCustody.retain()
                        ||!publicSurfaceRetirement.originalDetachCompleted()||profileDisplayReleaseAttempted
                        ||original==null||exact==null||exact!=publicCreateReturnedHandle||publicOwnGroupFramework==null
                        ||!publicOwnGroupFramework.hasFrozenIdentity()||SystemClock.elapsedRealtime()>=deadline)
                    throw new IOException("RETAINED_CLEANUP_ORIGINAL_CUSTODY_UNAVAILABLE");
                return original.cleanupRetained(deadline,new ProfileOwnedTask.RetiredDisplay(){
                    private java.util.Map<Integer,String> physical;
                    public void beginFreshSample(long began,long sampleDeadline)throws Exception{
                        long now=SystemClock.elapsedRealtime();
                        if(now<began||now>=sampleDeadline||sampleDeadline>deadline||sampleDeadline-began>1500)
                            throw new IOException("RETAINED_CLEANUP_SAMPLE_DEADLINE");
                        retainedReadDeadline.set(sampleDeadline);
                    }
                    public void requireState(boolean before)throws Exception{
                        if(SystemClock.elapsedRealtime()>=deadline||original!=profileOwnedTask||exact!=virtual
                                ||exact!=publicCreateReturnedHandle||!publicAdmissionRetired.get()||!closing.get()
                                ||serve||createInFlight||effectInFlight||cleanupDone.getCount()!=0)
                            throw new IOException("RETAINED_CLEANUP_OWNER_CHANGED");
                        if(before)publicOwnGroupFramework.requireRetiredDestroyHandle(displayId,displayName);
                        else if(!publicOwnedDisplayAbsent())throw new IOException("RETAINED_CLEANUP_DISPLAY_PRESENT");
                        final long readDeadline=Math.min(deadline,profileDeadline());
                        java.util.Map<Integer,String> actual=PublicOwnGroupPhysicalReader.read(windowManager,displays,
                                config.profileTarget.profile.userId,()->readDeadline);
                        if(physical==null)physical=actual;
                        else if(!physical.equals(actual))throw new IOException("RETAINED_CLEANUP_PHYSICAL_CHANGED");
                        if(SystemClock.elapsedRealtime()>=deadline)throw new IOException("RETAINED_CLEANUP_DEADLINE");
                    }
                    public void releaseOriginalHandle()throws Exception{throw new IOException("RETAINED_CLEANUP_CENSUS_START_REQUIRED");}
                    public void releaseOriginalHandle(long observedStarted,long expectedDeadline)throws Exception{
                        if(profileDisplayReleaseAttempted||exact!=virtual||exact!=publicCreateReturnedHandle
                                ||original!=profileOwnedTask||createInFlight||effectInFlight||expectedDeadline!=deadline||SystemClock.elapsedRealtime()>=deadline)
                            throw new IOException("RETAINED_CLEANUP_RELEASE_ALREADY_ATTEMPTED");
                        publicOwnGroupFramework.requireRetiredDestroyHandle(displayId,displayName);
                        long now=SystemClock.elapsedRealtime();
                        if(now<observedStarted||now>=deadline||now-observedStarted>=1500)
                            throw new IOException("RETAINED_CLEANUP_CENSUS_STALE");
                        profileDisplayReleaseAttempted=true;exact.release();
                        if(surfaceReader!=null)surfaceReader.close();
                        if(displayThread!=null)displayThread.quitSafely();
                    }
                    public void awaitAbsent()throws Exception{
                        while(!publicOwnedDisplayAbsent()){
                            if(SystemClock.elapsedRealtime()>=deadline)throw new IOException("RETAINED_CLEANUP_DISPLAY_PRESENT");
                            Thread.sleep(20);
                        }
                    }
                });
            }
        }finally{retainedReadDeadline.remove();}
    }
    private void awaitCleanup(long millis) {
        try { cleanupDone.await(Math.max(1, millis), TimeUnit.MILLISECONDS); }
        catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
    }
    private void closeSockets() {
        LocalSocket peer = connection; if (peer != null) try { peer.close(); } catch (IOException ignored) {}
        LocalServerSocket listening = server; if (listening != null) try { listening.close(); } catch (IOException ignored) {}
    }
    private byte[] response(BrokerProtocol.Request r, boolean ok, String error, boolean dispatched) throws Exception {
        DisplayGeometry geometry=displayGeometry;
        PublicOwnGroupPolicy.Readback publicReply=null;
        if(config.publicOwnGroupScope!=null&&r!=null&&ok&&"ACTIVE".equals(state)&&!closing.get()&&!publicAdmissionRetired.get()){
            publicScreenLease.requireActive();
            if(config.profileTarget!=null){
                if(profileOwnedTask==null)requireUnlaunchedProfileEmpty();
                else profileOwnedTask.verifyPublicRecentHistory();
            }
            publicReply=publicOwnGroupFramework.read(r.requestId,displayId,displayName);
            if(closing.get()||publicAdmissionRetired.get()||!"ACTIVE".equals(state))throw new BrokerProtocol.Refusal("PUBLIC_SCOPE_RETIRED_DURING_READ");
        }
        JSONObject value = new JSONObject().put("version", config.protocolVersion())
            .put("request_id", r == null ? JSONObject.NULL : r.requestId).put("generation", config.generation)
            .put("ok", ok).put("state", state).put("display_id", displayId).put("flags", displayFlags)
            .put("width", geometry==null?JSONObject.NULL:geometry.width)
            .put("height", geometry==null?JSONObject.NULL:geometry.height)
            .put("density", geometry==null?JSONObject.NULL:geometry.density)
            .put("display_geometry_snapshot",geometry==null?JSONObject.NULL:new JSONObject(geometry.evidence()))
            .put("display_geometry_readback",displayGeometryReadback==null?JSONObject.NULL:new JSONObject(displayGeometryReadback.toString()))
            .put("dispatched", dispatched).put("display_name", displayName)
            .put("expires_elapsed_ms", expires).put("capture_secure", false).put("always_unlocked", config.publicOwnGroupScope!=null)
            .put("ime_policy", "hide")
            .put("display_policy_readback", displayPolicyReadback==null?JSONObject.NULL:new JSONObject(displayPolicyReadback.toString()));
        if(config.publicOwnGroupScope!=null){
            value.put("display_scope_sha256",config.publicOwnGroupScope.sha256)
                .put("public_own_group_readback_wire",publicReply==null?JSONObject.NULL:publicReply.wire())
                .put("public_scope_admission_retired",publicAdmissionRetired.get()).put("public_scope_closing",closing.get()).put("public_surface_detach",publicDetachEvidence())
                .put("public_task_location",publicTaskFence==null?JSONObject.NULL:new JSONObject(publicTaskFence.evidence()))
                .put("public_profile_recent_history",publicProfileHistory==null?JSONObject.NULL:new JSONObject(publicProfileHistory.evidence()))
                .put("public_policy_diagnostics",new JSONObject(publicPolicyFailures.evidence()));
        }
        if(r!=null&&r.requestId.equals(calendarProbeRequest)&&calendarProbeEvidence!=null)
            value.put("calendar_window_probe",new JSONObject(calendarProbeEvidence.toString()));
        if(r!=null&&r.requestId.equals(calendarDateRequest)&&calendarDateEvidence!=null)
            value.put("calendar_date_input",new JSONObject(calendarDateEvidence.toString()));
        if (r != null) {value.put("operation", r.operation);
            if(fixedIntentProofs.containsKey(r.requestId))value.put("fixed_intent",fixedIntentProofs.get(r.requestId));
            if(taskLaunchPolicies.containsKey(r.requestId))value.put("task_launch_policy",taskLaunchPolicies.get(r.requestId));
        }
        if(ownedSingleTask!=null)value.put("owned_single_task",new JSONObject(ownedSingleTask.evidence()));
        if(publicNotesCustody!=null)value.put("personal_notes_cleanup",new JSONObject(publicNotesCustody.evidence()))
                .put("personal_notes_task_info_diagnostics",new JSONObject(publicNotesReadFailures.evidence()));
        if(permissionControllerUi!=null)value.put("permission_controller_ui",new JSONObject(permissionControllerUi.evidence()));
        if(config.publicOwnGroupScope!=null&&permissionProjectionBaseline!=null){
            value.put("profile_initialization_physical_audit",new JSONObject().put("schema","hepta.public-profile-initialization-physical-audit.v1")
                    .put("baseline",new JSONObject().put("0",permissionPhysicalBaseline.get(0)).put("1",permissionPhysicalBaseline.get(1)))
                    .put("latest_completed",new JSONObject().put("0",permissionPhysicalAudit.get(0)).put("1",permissionPhysicalAudit.get(1)))
                    .put("whole_physical_snapshot_equal",permissionPhysicalBaseline.equals(permissionPhysicalAudit))
                    .put("physical_user_activity_frozen",false).put("controls_admission",false)
                    .put("ownership_projection",new JSONObject(permissionProjectionBaseline.evidence())));
        }
        if(config.profileTarget!=null){
            ProfilePackages.Readback actual=profileReadback;
            java.util.Map<String,Object> cleanup=profileCleanupReadback;
            if(cleanup==null)cleanup=emptyProfileCleanup(false);
            value.put("profile_target_wire",actual==null?JSONObject.NULL:actual.target.wire())
                    .put("profile_current_identity_verified",ok&&"ACTIVE".equals(state)&&actual!=null
                            &&config.profileTarget.same(actual.target))
                    .put("profile_cleanup",new JSONObject(cleanup))
                    .put("profile_cleanup_diagnostics",new JSONObject(profileCleanupFailures.evidence()))
                    .put("profile_last_leaf_validation",profileOwnedTask==null?JSONObject.NULL:
                            new JSONObject(profileOwnedTask.lastLeafValidation()))
                    .put("profile_first_root_refusal",profileOwnedTask==null?JSONObject.NULL:
                            new JSONObject(profileOwnedTask.firstRootRefusal()))
                    .put("profile_permission_first_read_mismatch",profileOwnedTask==null?JSONObject.NULL:
                            new JSONObject(profileOwnedTask.firstPermissionReadMismatch()))
                    .put("profile_personal_task_audit",profilePersonalAudit==null?JSONObject.NULL:new JSONObject(profilePersonalAudit))
                    .put("profile_cleanup_known",Boolean.TRUE.equals(cleanup.get("cleanup_known")))
                    .put("profile_custody_retained",closing.get()&&profileCustody.retain());
            WindowOwnership window=profileWindow;
            if(r!=null&&window!=null&&r.requestId.equals(profileWindowRequest))value.put("window_ownership_wire",window.wire());
            value.put("profile_permission_preparing",profilePreparing).put("profile_permission_preparation_state",profilePreparationState);
            if("prepare_done".equals(r==null?null:r.operation))
                value.put("profile_confirmation_sample",profileConfirmationSample).put("profile_confirmation_deferred",profileConfirmationDeferred);
            PermissionWindowObservation permission=permissionWindow;
            if(r!=null&&permission!=null&&r.requestId.equals(permissionWindowRequest))
                value.put("permission_window_wire",permission.wire());
        }
        if (error != null) {
            value.put("error", error);
            if("PUBLIC_SCOPE_POLICY_UNAVAILABLE".equals(error)||"PUBLIC_SCOPE_POLICY_UNAVAILABLE".equals(terminalReason)){
                String explanation=publicPolicyFailures.summary();
                if(!explanation.isEmpty())value.put("message",explanation);
            }
        }
        if (!terminalReason.isEmpty()) value.put("terminal_reason", terminalReason);
        return value.toString().getBytes(StandardCharsets.UTF_8);
    }
    private void printTerminal() {
        try { JSONObject terminal=new JSONObject().put("schema", "hepta.background-broker-terminal.v1")
            .put("generation", config.generation).put("state", state).put("display_id", displayId)
            .put("reason", terminalReason).put("release_confirmed", "RELEASED".equals(state))
            .put("boot_count_read_retirement_failure",bootReadRetirementFailure==null?JSONObject.NULL:bootReadRetirementFailure)
            .put("owned_single_task",ownedSingleTask==null?JSONObject.NULL:new JSONObject(ownedSingleTask.evidence()))
            .put("profile_cleanup",config.profileTarget==null?JSONObject.NULL:new JSONObject(
                    profileCleanupReadback==null?emptyProfileCleanup(false):profileCleanupReadback))
            .put("profile_cleanup_diagnostics",new JSONObject(profileCleanupFailures.evidence()))
            .put("profile_last_leaf_validation",profileOwnedTask==null?JSONObject.NULL:
                    new JSONObject(profileOwnedTask.lastLeafValidation()))
            .put("profile_first_root_refusal",profileOwnedTask==null?JSONObject.NULL:
                    new JSONObject(profileOwnedTask.firstRootRefusal()))
            .put("profile_permission_first_read_mismatch",profileOwnedTask==null?JSONObject.NULL:
                    new JSONObject(profileOwnedTask.firstPermissionReadMismatch()))
            .put("profile_custody_retained",config.profileTarget!=null&&profileCustody.retain());
            if(config.publicOwnGroupScope!=null)terminal.put("display_scope_sha256",config.publicOwnGroupScope.sha256)
                    .put("public_scope_admission_retired",publicAdmissionRetired.get()).put("public_surface_detach",publicDetachEvidence())
                    .put("public_screen_lease",new JSONObject(publicScreenLease.evidence()))
                    .put("public_policy_diagnostics",new JSONObject(publicPolicyFailures.evidence()));
            if(!retainedRecheckOutcome.isEmpty())terminal.put("profile_retained_recheck_outcome",retainedRecheckOutcome);
            if(publicNotesCustody!=null)terminal.put("personal_notes_cleanup",new JSONObject(publicNotesCustody.evidence()))
                    .put("personal_notes_task_info_diagnostics",new JSONObject(publicNotesReadFailures.evidence()));
            if(config.publicOwnGroupScope!=null)appendNotesHistoryDiagnostic(terminal,publicNotesCleanupFailure,
                    config.publicOwnGroupScope.taskId,config.generation,config.publicOwnGroupScope.sha256,displayId);
            System.out.println(terminal); }
        catch (Throwable ignored) { System.err.println("terminal_receipt_unavailable"); }
    }
    /** Diagnostic-only augmentation of the original single terminal object.
     * No protocol/journal fields or cleanup decisions consume this field. */
    static void appendNotesHistoryDiagnostic(JSONObject terminal,Throwable error,String task,String generation,String scope,int display){
        try{
            java.util.Map<String,Object> detail=PublicPersonalNotesRetirement.historyDiagnostic(error);
            if(detail==null)return;
            JSONObject value=new JSONObject(detail).put("task_id",task).put("generation",generation)
                    .put("scope_sha256",scope).put("display_id",display).put("diagnostic_limit_bytes",4608)
                    .put("terminal_record_limit_bytes",32767);
            if(value.toString().getBytes(StandardCharsets.UTF_8).length>4608){
                value.remove("raw_pair");value.put("raw_pair_complete",false)
                        .put("raw_pair_omission_reason","serialized_diagnostic_bound");
            }
            JSONObject candidate=new JSONObject(terminal.toString()).put("personal_notes_history_diagnostic",value);
            if(candidate.toString().getBytes(StandardCharsets.UTF_8).length>32767){
                value.remove("raw_pair");value.put("raw_pair_complete",false)
                        .put("raw_pair_omission_reason","serialized_terminal_bound");
                candidate.put("personal_notes_history_diagnostic",value);
            }
            // The private diagnostic has its own smaller bound; no old bundle,
            // output, protocol or original-terminal bound is increased.
            if(value.toString().getBytes(StandardCharsets.UTF_8).length<=4608
                    &&candidate.toString().getBytes(StandardCharsets.UTF_8).length<=32767)
                terminal.put("personal_notes_history_diagnostic",value);
        }catch(Throwable ignored){/* Original refusal, terminal and custody stay decisive. */}
    }
    private static int fields(Class<?> type, String... names) throws Exception {
        int result = 0; for (String name : names) result |= type.getField(name).getInt(null); return result;
    }
    /** First cleanup failure only; fixed phases and bounded codes are diagnostic, never authority. */
    static final class ProfileCleanupFailureAudit {
        enum Phase {NOT_STARTED,TASK_RETIRE,UNLAUNCHED_PROFILE,DISPLAY_RELEASE,DISPLAY_ABSENCE,
            FINAL_PROFILE_IDENTITY,FINAL_GLOBAL_TASKS,FINAL_PUBLIC_RECENTS}
        private volatile Phase phase=Phase.NOT_STARTED;
        private java.util.Map<String,Object> first;
        void phase(Phase value){phase=value==null?Phase.NOT_STARTED:value;}
        synchronized void record(String reason,long started,long deadline,long now){
            if(first!=null)return;
            String code="cleanup_deadline".equals(reason)?"PROFILE_CLEANUP_DEADLINE":reason;
            if(code==null||!code.matches("[A-Z][A-Z0-9_]{0,127}"))code="PROFILE_CLEANUP_FAILURE_UNCLASSIFIED";
            java.util.Map<String,Object> row=new java.util.LinkedHashMap<String,Object>();
            row.put("phase",phase.name());row.put("code",code);row.put("observed_elapsed_ms",now);
            row.put("cleanup_started_elapsed_ms",started);row.put("task_reads_deadline_elapsed_ms",deadline);
            first=java.util.Collections.unmodifiableMap(row);
        }
        synchronized java.util.Map<String,Object> evidence(){
            java.util.Map<String,Object> out=new java.util.LinkedHashMap<String,Object>();
            out.put("schema","hepta.profile-cleanup-diagnostics.v1");out.put("first_failure",first);
            out.put("diagnostics_grant_authority",false);out.put("provides_cleanup_proof",false);
            out.put("allows_input_or_model_resumption",false);
            return java.util.Collections.unmodifiableMap(out);
        }
    }

    /** First unexpected policy failure only. This evidence never changes admission or cleanup. */
    static final class PublicPolicyFailureAudit {
        enum Phase {
            FRAMEWORK_SELECTION, FRAMEWORK_PREFLIGHT, FRAMEWORK_READ,
            SCREEN_LEASE, PERSONAL_TASK_LOCATION, TASK_LOCATION_CENSUS, NOTES_FRAME_AND_CUSTODY
        }
        private java.util.Map<String,Object> first;
        synchronized void record(Phase phase,Exception error,long now) {
            if(first!=null)return;
            Throwable cause=error;int wrappers=0;
            while(cause instanceof InvocationTargetException&&wrappers<8){
                Throwable next=((InvocationTargetException)cause).getTargetException();
                if(next==null||next==cause)break;
                cause=next;wrappers++;
            }
            java.util.Map<String,Object> row=new java.util.LinkedHashMap<String,Object>();
            row.put("phase",phase==null?"UNKNOWN":phase.name());
            row.put("observed_elapsed_ms",now);
            row.put("exception_class",className(error));
            row.put("cause_class",className(cause));
            row.put("reflection_wrapper_count",wrappers);
            row.put("category",category(cause));
            first=java.util.Collections.unmodifiableMap(row);
        }
        synchronized java.util.Map<String,Object> evidence(){
            java.util.Map<String,Object> out=new java.util.LinkedHashMap<String,Object>();
            out.put("schema","hepta.public-policy-diagnostics.v1");
            out.put("first_failure",first);
            out.put("diagnostics_grant_authority",false);
            out.put("provides_cleanup_proof",false);
            return java.util.Collections.unmodifiableMap(out);
        }
        synchronized String summary(){
            if(first==null)return "";
            String phase=(String)first.get("phase"),category=(String)first.get("category");
            String stage;
            switch(phase){
                case "FRAMEWORK_PREFLIGHT":stage="后台显示启动检查";break;
                case "FRAMEWORK_READ":stage="后台显示策略读回";break;
                case "SCREEN_LEASE":stage="后台屏幕租约";break;
                case "PERSONAL_TASK_LOCATION":stage="应用任务位置检查";break;
                case "TASK_LOCATION_CENSUS":stage="后台任务隔离检查";break;
                case "NOTES_FRAME_AND_CUSTODY":stage="笔记任务读回";break;
                default:stage="后台策略检查";
            }
            String reason;
            switch(category){
                case "PUBLIC_SCREEN_NOT_ON":reason="后台屏幕未保持亮屏";break;
                case "PUBLIC_SCREEN_LEASE_NOT_HELD":reason="后台屏幕租约未持有";break;
                case "PUBLIC_SCREEN_LEASE_RETIRED":reason="后台屏幕租约已终止";break;
                case "PUBLIC_SCREEN_LIFETIME_IDENTITY_CHANGED":reason="后台屏幕身份发生变化";break;
                case "FRAMEWORK_PERMISSION_DENIED":reason="系统权限检查拒绝";break;
                case "FRAMEWORK_API_UNAVAILABLE":reason="所需系统接口不可用";break;
                case "FRAMEWORK_REFLECTION_ACCESS_DENIED":reason="系统接口访问被拒绝";break;
                case "FRAMEWORK_TIMEOUT":reason="系统读取超时";break;
                case "WRAPPED_POLICY_REFUSAL":reason="系统读回未满足隔离规则";break;
                case "IO_FAILURE":reason="系统读取失败";break;
                case "FRAMEWORK_STATE_UNAVAILABLE":reason="系统状态不可用";break;
                case "FRAMEWORK_ARGUMENT_REJECTED":reason="系统接口拒绝参数";break;
                default:reason="系统检查发生异常";
            }
            return stage+"未通过："+reason+"（"+phase+" / "+category+"）。";
        }
        private static String className(Throwable error){
            if(error==null)return "UNKNOWN";
            String name=error.getClass().getName();
            return name.length()<=192&&name.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*")
                    ?name:"OTHER_EXCEPTION_CLASS";
        }
        private static String category(Throwable error){
            if(error instanceof BrokerProtocol.Refusal)return "WRAPPED_POLICY_REFUSAL";
            if(error instanceof SecurityException)return "FRAMEWORK_PERMISSION_DENIED";
            if(error instanceof NoSuchFieldException||error instanceof NoSuchMethodException||error instanceof ClassNotFoundException)
                return "FRAMEWORK_API_UNAVAILABLE";
            if(error instanceof IllegalAccessException)return "FRAMEWORK_REFLECTION_ACCESS_DENIED";
            if(error instanceof java.util.concurrent.TimeoutException)return "FRAMEWORK_TIMEOUT";
            if(error instanceof IOException){
                // Compare only fixed public policy tokens; never retain arbitrary exception text.
                String reason=error.getMessage();
                if("PUBLIC_SCREEN_NOT_ON".equals(reason))return "PUBLIC_SCREEN_NOT_ON";
                if("PUBLIC_SCREEN_LEASE_NOT_HELD".equals(reason))return "PUBLIC_SCREEN_LEASE_NOT_HELD";
                if("PUBLIC_SCREEN_LEASE_RETIRED".equals(reason))return "PUBLIC_SCREEN_LEASE_RETIRED";
                if("PUBLIC_SCREEN_LIFETIME_IDENTITY_CHANGED".equals(reason))return "PUBLIC_SCREEN_LIFETIME_IDENTITY_CHANGED";
                return "IO_FAILURE";
            }
            if(error instanceof IllegalStateException)return "FRAMEWORK_STATE_UNAVAILABLE";
            if(error instanceof IllegalArgumentException)return "FRAMEWORK_ARGUMENT_REJECTED";
            if(error instanceof RuntimeException)return "FRAMEWORK_RUNTIME_FAILURE";
            return "FRAMEWORK_CHECKED_FAILURE";
        }
    }

    private static String code(Throwable error) {
        while (error instanceof InvocationTargetException && ((InvocationTargetException) error).getCause() != null)
            error = ((InvocationTargetException) error).getCause();
        if (error instanceof BrokerProtocol.Refusal) return ((BrokerProtocol.Refusal) error).code;
        if (error instanceof InputChannelIsolation.Refusal) return ((InputChannelIsolation.Refusal) error).code;
        if (error instanceof BackgroundOwnedSingleTask.Refusal) return ((BackgroundOwnedSingleTask.Refusal) error).code;
        if (error instanceof ProfileTaskPolicy.Refusal) return ((ProfileTaskPolicy.Refusal) error).code;
        if (error instanceof SecurityException) return "FRAMEWORK_PERMISSION_DENIED";
        if (error instanceof NoSuchFieldException || error instanceof NoSuchMethodException || error instanceof ClassNotFoundException)
            return "FRAMEWORK_API_UNAVAILABLE";
        if (error instanceof IOException) {
            String message=error.getMessage();
            if(message!=null&&message.matches("PROFILE_[A-Z0-9_]{1,96}"))return message;
            return "TRANSPORT_IO_ERROR";
        }
        return "FRAMEWORK_OPERATION_FAILED";
    }
}
