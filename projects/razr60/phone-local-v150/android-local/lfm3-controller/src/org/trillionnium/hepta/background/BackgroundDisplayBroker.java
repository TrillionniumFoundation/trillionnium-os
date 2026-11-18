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
import android.os.SystemClock;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.InputDevice;
import android.view.InputEvent;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
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
    private final Object dispatchGate = new Object();
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
    private volatile int displayId = -1;
    private volatile int displayFlags;
    private volatile JSONObject displayPolicyReadback;
    private volatile PublicOwnGroupFramework publicOwnGroupFramework;
    private volatile boolean publicOwnGroupDisplayReady;
    private volatile PublicOwnGroupPolicy.Readback publicOwnGroupLastReadback;
    private final AtomicBoolean publicAdmissionRetired=new AtomicBoolean();
    private final PublicOwnGroupSurfaceRetirement publicSurfaceRetirement=new PublicOwnGroupSurfaceRetirement();
    // Only the object actually returned by this session's create API. Never reconstructed from an id or wire.
    private volatile VirtualDisplay publicCreateReturnedHandle;
    private volatile PublicOwnGroupTaskFence publicTaskFence;
    private volatile PublicPersonalNotesCustody publicNotesCustody;
    private volatile PublicPersonalNotesReader publicNotesReader;
    private volatile DisplayGeometry displayGeometry;
    private volatile JSONObject displayGeometryReadback;
    private final java.util.Map<String,Integer> displayFlagConstants=new java.util.LinkedHashMap<String,Integer>();
    private volatile LocalSocket connection;
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
    private volatile java.util.Map<Integer,String> permissionPhysicalBaseline;
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
    private final Set<String> fixedToolsConsumed=new HashSet<String>();
    private final java.util.Map<String,JSONObject> fixedIntentProofs=new java.util.LinkedHashMap<String,JSONObject>();
    private final java.util.Map<String,JSONObject> taskLaunchPolicies=new java.util.LinkedHashMap<String,JSONObject>();

    private BackgroundDisplayBroker(BrokerProtocol.Config config) throws BrokerProtocol.Refusal {
        this.config = config;
        if (config.expiresElapsedMs <= started) throw new BrokerProtocol.Refusal("START_EXPIRED");
        if(config.publicOwnGroupScope!=null&&config.publicOwnGroupScope.createdElapsedMs>started)
            throw new BrokerProtocol.Refusal("PUBLIC_SCOPE_CREATED_IN_FUTURE");
        expires = Math.min(started + config.ttlMs, config.expiresElapsedMs);
        displayName = "hepta-bg-" + config.generation;
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
                catch (Throwable error) { shutdown(code(error)); return; }
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
                    response = receipts.replay(request);
                    if (response == null) {
                        request.checkDeadline(SystemClock.elapsedRealtime(), expires);
                        requestDeadline = Math.min(request.deadline, expires);
                        connectionDeadline = requestDeadline;
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
                    retired.put("ok",false).put("error","PUBLIC_SCOPE_RETIRED").put("state",state)
                        .put("public_scope_admission_retired",true).put("public_scope_closing",true)
                        .put("public_own_group_readback_wire",JSONObject.NULL).put("public_surface_detach",publicDetachEvidence());
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
                connection = null; requestDeadline = 0; connectionDeadline = 0;
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
                permissionPhysicalBaseline=permissionPhysicalFence(r);profilePreparing=true;
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
                if(!before.equals(after))throw new BrokerProtocol.Refusal("PROFILE_PERMISSION_PHYSICAL_CHANGED_DURING_READ");
                guard(r,true);permissionWindow=PermissionWindowObservation.fromLive(read,after,SystemClock.elapsedRealtime());
                permissionWindowRequest=r.requestId;profilePreparationState="PERMISSION_PENDING";refreshProfileTaskEvidence();
            } else if(config.profileTarget!=null&&"prepare_done".equals(r.operation)) {
                requirePermissionPreparing(r);
                if(!"APP_READY".equals(profileOwnedTask.initializationState(Math.min(r.deadline,expires))))
                    throw new BrokerProtocol.Refusal("PROFILE_PERMISSION_SETUP_REQUIRED");
                requirePermissionPhysicalUnchanged(permissionPhysicalFence(r));
                if(!profileOwnedTask.observe())throw new BrokerProtocol.Refusal("PROFILE_TASK_NOT_OBSERVED");
                profilePreparing=false;profilePreparationState="COMPLETE";refreshProfileTaskEvidence();
            } else if(config.profileTarget!=null&&"launch".equals(r.operation)) {
                dispatched=launchProfile(r);
            } else if(config.profileTarget!=null&&"window".equals(r.operation)) {
                guard(r,true);
                if(profileOwnedTask==null)throw new BrokerProtocol.Refusal("PROFILE_TASK_NOT_ACTIVE");
                profileWindow=profileOwnedTask.window(r.windowId,r.observedTaskId,Math.min(r.deadline,expires));
                profileWindowRequest=r.requestId;
                refreshProfileTaskEvidence();
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
        ProfilePackages.Readback actual=profilePackages.read(config.profileTarget.profile.userId,ready,deadline);
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
        guard(r,true);java.util.Map<Integer,String> value=config.publicOwnGroupScope==null?
                ProfilePermissionPhysicalReader.read(windowManager,displays,config.profileTarget.profile.userId,()->Math.min(r.deadline,expires)):
                PublicOwnGroupPhysicalReader.read(windowManager,displays,config.profileTarget.profile.userId,()->Math.min(r.deadline,expires));
        guard(r,true);return value;
    }
    private void requirePermissionPhysicalUnchanged(java.util.Map<Integer,String> actual)throws Exception{
        if(permissionPhysicalBaseline==null||!permissionPhysicalBaseline.equals(actual))
            throw new BrokerProtocol.Refusal("PROFILE_PERMISSION_PHYSICAL_DISPLAY_CHANGED");
    }
    private boolean launchProfile(BrokerProtocol.Request r)throws Exception{return launchProfile(r,false);}
    private boolean launchProfile(BrokerProtocol.Request r,boolean initialization)throws Exception {
        guard(r,true);
        if(profileOwnedTask!=null)throw new BrokerProtocol.Refusal("PROFILE_LAUNCH_ALREADY_ATTEMPTED");
        final ProfileTaskPolicy.Activity initial=profileReadback.activity;
        initial.requireEligible(config.profileTarget);
        final ComponentName component=ComponentName.unflattenFromString(profileReadback.target.component);
        if(component==null)throw new BrokerProtocol.Refusal("PROFILE_LAUNCHER_UNAVAILABLE");
        final Intent intent=new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
                .setComponent(component).setPackage(r.packageName)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_MULTIPLE_TASK);
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
            try{
                PublicOwnGroupFramework framework=publicOwnGroupFramework;
                if(framework==null)throw new BrokerProtocol.Refusal("PUBLIC_SCOPE_FRAMEWORK_UNAVAILABLE");
                if(publicOwnGroupDisplayReady)framework.read(config.generation,displayId,displayName);
                else framework.preflight();
                // New personal mode keeps the original package-location rule on
                // fresh policy reads too; user activity in other apps stays free.
                if(config.profileTarget==null&&displayId>1)verifyLaunchedLocations(snapshot());
                PublicOwnGroupTaskFence taskFence=publicTaskFence;
                if(taskFence!=null&&displayId>1)taskFence.observe(BackgroundTaskOrganizer.profileSnapshot(activityTasks),displayId,SystemClock.elapsedRealtime());
                if(publicNotesCustody!=null&&publicNotesReader!=null)
                    publicNotesCustody.observe(publicNotesReader.frame(),SystemClock.elapsedRealtime());
                lastUnlockedCheck=SystemClock.elapsedRealtime();return;
            }catch(BrokerProtocol.Refusal refusal){throw refusal;}
            catch(Exception unavailable){throw new BrokerProtocol.Refusal("PUBLIC_SCOPE_POLICY_UNAVAILABLE");}
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
                if(config.publicOwnGroupScope!=null)publicSurfaceRetirement.observeDeadline(now);
                if (cleanupStarted.get() && now - cleanupAt >= CLEANUP_MS) {
                    boolean known = cleanupDone.getCount() == 0 && "RELEASED".equals(state);
                    if(config.profileTarget!=null&&profileCustody.known()){
                        state=releasedState();haltAfterBootRead(0);
                    }
                    if(config.profileTarget!=null&&profileCustody.retain()){
                        quarantineProfile("cleanup_deadline");printTerminal();return;
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

    private void shutdown(String reason) {
        serve = false; beginCleanup(reason); closeSockets();
    }

    private void retireBootRead() {
        try { publicBootCount.abortForDeadline(); }
        catch(Throwable failure) { bootReadRetirementFailure=failure.getClass().getName(); }
    }

    private String releasedState() {
        return bootReadRetirementFailure==null?"RELEASED":"CLEANUP_UNKNOWN";
    }

    private void haltAfterBootRead(int exit) {
        try {
            retireBootRead();
            if(bootReadRetirementFailure!=null)state="CLEANUP_UNKNOWN";
            printTerminal();
        }
        finally { Runtime.getRuntime().halt(bootReadRetirementFailure==null?exit:70); }
    }

    private void beginCleanup(String reason) {
        closing.set(true);
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
                synchronized(dispatchGate){
                    if(!custody.createAttempted()){
                        if(virtual!=null||createInFlight||effectInFlight)throw new IOException("NOTES_CREATE_STATE_UNKNOWN");
                        custody.notCreated();state=releasedState();return;
                    }
                    PublicPersonalNotesReader reader=publicNotesReader;
                    if(reader==null||virtual==null||virtual!=publicCreateReturnedHandle||createInFlight||effectInFlight)
                        throw new IOException("NOTES_OWNED_DISPLAY_OR_READER_UNKNOWN");
                    PublicPersonalNotesCustody.Frame before=reader.frame();
                    PublicOwnGroupPhysicalFence.RecentCensus beforeRecents=reader.recents();
                    custody.prepareRelease(before,beforeRecents,SystemClock.elapsedRealtime());
                    // Only this session's actual create-returned VD handle is released.
                    // No per-task remove, reparent, caller-supplied id or process kill.
                    if(virtual!=publicCreateReturnedHandle)throw new IOException("NOTES_OWNED_DISPLAY_CHANGED");
                    custody.enterRelease();virtual.release();custody.releaseReturned();
                    ImageReader images=surfaceReader;if(images!=null)images.close();
                    HandlerThread worker=displayThread;if(worker!=null)worker.quitSafely();
                }
                long end=cleanupAt+CLEANUP_MS-100;
                while(SystemClock.elapsedRealtime()<end){
                    if(!publicOwnedDisplayAbsent()){Thread.sleep(25);continue;}
                    long begin=SystemClock.elapsedRealtime();
                    ProfileTaskPolicy.Snapshot live=publicNotesReader.global();
                    PublicPersonalNotesCustody.Frame remaining=null;
                    if(custody.needsActualTasks(live)){remaining=publicNotesReader.frame();live=remaining.global;}
                    PublicOwnGroupPhysicalFence.RecentCensus recents=publicNotesReader.recents();
                    long finish=SystemClock.elapsedRealtime();
                    custody.observeAbsence(live,recents,remaining,publicOwnedDisplayAbsent(),begin,finish,SystemClock.elapsedRealtime());
                    if(custody.known()){state=releasedState();return;}
                    Thread.sleep(50);
                }
                throw new IOException("NOTES_CLEANUP_ABSENCE_DEADLINE");
            }catch(Throwable error){quarantinePublicNotes(error.getMessage());}
            finally{cleanupDone.countDown();}
        },"HeptaPublicNotesCleanup");cleanup.setDaemon(true);cleanup.start();
        }catch(Throwable scheduling){quarantinePublicNotes("NOTES_CLEANUP_WORKER_UNAVAILABLE");cleanupDone.countDown();}
    }
    private boolean publicOwnedDisplayAbsent()throws Exception{
        DisplayManager manager=displays;
        if(manager==null)return false;
        if(displayId>0&&manager.getDisplay(displayId)!=null)return false;
        Display[] all=manager.getDisplays();if(all==null)return false;
        for(Display value:all)if(value==null||displayName.equals(value.getName()))return false;
        return true;
    }
    private void quarantinePublicNotes(String reason){
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
                        tasks.retire(cleanupAt+CLEANUP_MS-100);
                        refreshProfileTaskEvidence();
                        if(!tasks.cleanupKnown())throw new IOException("PROFILE_TASK_RETIRE_UNCONFIRMED");
                    }else{
                        recheckProfile(false,cleanupAt+CLEANUP_MS-100);
                        requireUnlaunchedProfileEmpty();
                        profileCleanupReadback=emptyProfileCleanup(true);
                    }
                    profileCustody.tasksVerified();
                    // The watchdog can mark uncertainty while a Binder call is in flight. It is
                    // monotonic: an observed quarantine refuses a new release call. A release
                    // already in flight can still time out; its custodian then remains alive.
                    if(!profileCustody.mayRelease())throw new IOException("PROFILE_CUSTODY_QUARANTINED");
                    VirtualDisplay owned=virtual;
                    if(owned!=null)owned.release();
                    ImageReader reader=surfaceReader;if(reader!=null)reader.close();
                    HandlerThread worker=displayThread;if(worker!=null)worker.quitSafely();
                }
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
                    recheckProfile(false,cleanupAt+CLEANUP_MS-100);
                    BackgroundTaskOrganizer.profileSnapshot(activityTasks).requireDedicatedEmpty(config.profileTarget);
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
    private void holdProfileCustody(){
        // Retaining the live binder owner is intentional. DESTROY_CONTENT_ON_REMOVAL remains
        // enabled; removing that flag would allow main-display migration instead. Unexpected
        // SIGKILL, OS process death or power loss is still UNKNOWN, never a cleanup proof.
        while(config.profileTarget!=null&&profileCustody.retain()){
            try{Thread.sleep(250);}catch(InterruptedException ignored){}
        }
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
                .put("public_profile_recent_history",publicProfileHistory==null?JSONObject.NULL:new JSONObject(publicProfileHistory.evidence()));
        }
        if (r != null) {value.put("operation", r.operation);
            if(fixedIntentProofs.containsKey(r.requestId))value.put("fixed_intent",fixedIntentProofs.get(r.requestId));
            if(taskLaunchPolicies.containsKey(r.requestId))value.put("task_launch_policy",taskLaunchPolicies.get(r.requestId));
        }
        if(ownedSingleTask!=null)value.put("owned_single_task",new JSONObject(ownedSingleTask.evidence()));
        if(publicNotesCustody!=null)value.put("personal_notes_cleanup",new JSONObject(publicNotesCustody.evidence()));
        if(config.profileTarget!=null){
            ProfilePackages.Readback actual=profileReadback;
            java.util.Map<String,Object> cleanup=profileCleanupReadback;
            if(cleanup==null)cleanup=emptyProfileCleanup(false);
            value.put("profile_target_wire",actual==null?JSONObject.NULL:actual.target.wire())
                    .put("profile_current_identity_verified",ok&&"ACTIVE".equals(state)&&actual!=null
                            &&config.profileTarget.same(actual.target))
                    .put("profile_cleanup",new JSONObject(cleanup))
                    .put("profile_last_leaf_validation",profileOwnedTask==null?JSONObject.NULL:
                            new JSONObject(profileOwnedTask.lastLeafValidation()))
                    .put("profile_personal_task_audit",profilePersonalAudit==null?JSONObject.NULL:new JSONObject(profilePersonalAudit))
                    .put("profile_cleanup_known",Boolean.TRUE.equals(cleanup.get("cleanup_known")))
                    .put("profile_custody_retained",closing.get()&&profileCustody.retain());
            WindowOwnership window=profileWindow;
            if(r!=null&&window!=null&&r.requestId.equals(profileWindowRequest))value.put("window_ownership_wire",window.wire());
            value.put("profile_permission_preparing",profilePreparing).put("profile_permission_preparation_state",profilePreparationState);
            PermissionWindowObservation permission=permissionWindow;
            if(r!=null&&permission!=null&&r.requestId.equals(permissionWindowRequest))
                value.put("permission_window_wire",permission.wire());
        }
        if (error != null) value.put("error", error);
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
            .put("profile_last_leaf_validation",profileOwnedTask==null?JSONObject.NULL:
                    new JSONObject(profileOwnedTask.lastLeafValidation()))
            .put("profile_custody_retained",config.profileTarget!=null&&profileCustody.retain());
            if(config.publicOwnGroupScope!=null)terminal.put("display_scope_sha256",config.publicOwnGroupScope.sha256)
                    .put("public_scope_admission_retired",publicAdmissionRetired.get()).put("public_surface_detach",publicDetachEvidence());
            if(publicNotesCustody!=null)terminal.put("personal_notes_cleanup",new JSONObject(publicNotesCustody.evidence()));
            System.out.println(terminal); }
        catch (Throwable ignored) { System.err.println("terminal_receipt_unavailable"); }
    }
    private static int fields(Class<?> type, String... names) throws Exception {
        int result = 0; for (String name : names) result |= type.getField(name).getInt(null); return result;
    }
    private static String code(Throwable error) {
        while (error instanceof InvocationTargetException && ((InvocationTargetException) error).getCause() != null)
            error = ((InvocationTargetException) error).getCause();
        if (error instanceof BrokerProtocol.Refusal) return ((BrokerProtocol.Refusal) error).code;
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
