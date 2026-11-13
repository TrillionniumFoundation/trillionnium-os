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
    public static final int WIDTH = 720, HEIGHT = 1280, DENSITY = 240;
    private static final long STARTUP_MS = 8000, SOCKET_MS = 3000, CLEANUP_MS = 1500;
    private final BrokerProtocol.Config config;
    private final BrokerProtocol.Receipts receipts = new BrokerProtocol.Receipts();
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
    private final Set<String> fixedToolsConsumed=new HashSet<String>();
    private final java.util.Map<String,JSONObject> fixedIntentProofs=new java.util.LinkedHashMap<String,JSONObject>();
    private final java.util.Map<String,JSONObject> taskLaunchPolicies=new java.util.LinkedHashMap<String,JSONObject>();

    private BackgroundDisplayBroker(BrokerProtocol.Config config) throws BrokerProtocol.Refusal {
        this.config = config;
        if (config.expiresElapsedMs <= started) throw new BrokerProtocol.Refusal("START_EXPIRED");
        expires = Math.min(started + config.ttlMs, config.expiresElapsedMs);
        displayName = "hepta-bg-" + config.generation;
    }

    public static void main(String[] args) {
        BackgroundDisplayBroker broker = null;
        int exit = 0;
        try {
            int uid = android.os.Process.myUid();
            if (uid != 0 && uid != 2000) throw new BrokerProtocol.Refusal("BROKER_REQUIRES_EXISTING_SHELL_OR_ROOT");
            broker = new BackgroundDisplayBroker(BrokerProtocol.Config.parse(args));
            final BackgroundDisplayBroker owner = broker;
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                owner.beginCleanup("process_shutdown");
                owner.awaitCleanup(CLEANUP_MS);
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
        requireUnlocked();
        virtualFlags = fields(DisplayManager.class, "VIRTUAL_DISPLAY_FLAG_PUBLIC", "VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY",
            "VIRTUAL_DISPLAY_FLAG_SUPPORTS_TOUCH", "VIRTUAL_DISPLAY_FLAG_DESTROY_CONTENT_ON_REMOVAL",
            "VIRTUAL_DISPLAY_FLAG_TRUSTED", "VIRTUAL_DISPLAY_FLAG_OWN_FOCUS", "VIRTUAL_DISPLAY_FLAG_STEAL_TOP_FOCUS_DISABLED");
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
        snapshot(); // Required privileged unfiltered task query; unsupported access fails before a display exists.
        checkOwnerPackages();
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
        try {
            if ("close".equals(r.operation)) {
                beginCleanup("client_close");
                awaitCleanup(Math.max(1, Math.min(CLEANUP_MS, r.deadline - SystemClock.elapsedRealtime())));
                return response(r, "RELEASED".equals(state), "RELEASED".equals(state) ? null : "CLEANUP_NOT_CONFIRMED", false);
            }
            guard(r, false);
            if ("create".equals(r.operation)) {
                if ("ACTIVE".equals(state)) { verifyDisplay(); return response(r, true, null, false); }
                if (!"INITIAL".equals(state)) throw new BrokerProtocol.Refusal("SESSION_NOT_CREATABLE");
                synchronized (dispatchGate) {
                  guard(r, false);
                  createInFlight = true;
                  try {
                    ensureNameAbsent();
                    displayThread = new HandlerThread("HeptaBackgroundSurface"); displayThread.start();
                    Handler handler = new Handler(displayThread.getLooper());
                    surfaceReader = ImageReader.newInstance(WIDTH, HEIGHT, PixelFormat.RGBA_8888, 3);
                    surfaceReader.setOnImageAvailableListener(reader -> {
                        try (Image image = reader.acquireLatestImage()) {
                            if (image == null) return; // Drain without observing or copying pixels.
                        }
                        catch (Throwable error) { if (!closing.get()) shutdown("SURFACE_DRAIN_FAILED"); }
                    }, handler);
                    guard(r, false);
                    dispatched = true;
                    VirtualDisplay created = displays.createVirtualDisplay(displayName, WIDTH, HEIGHT, DENSITY,
                        surfaceReader.getSurface(), virtualFlags);
                    virtual = created;
                    if (created == null) throw new BrokerProtocol.Refusal("DISPLAY_CREATION_FAILED");
                    displayId = created.getDisplay().getDisplayId();
                    if (displayId <= Display.DEFAULT_DISPLAY) throw new BrokerProtocol.Refusal("DEFAULT_DISPLAY_REFUSED");
                    if (closing.get()) throw new BrokerProtocol.Refusal("SESSION_CLOSING");
                    setImePolicy.invoke(windowManager, displayId, imeHide);
                    verifyDisplay();
                    guard(r, false);
                    state = "ACTIVE";
                  } finally { createInFlight = false; }
                }
            } else if ("state".equals(r.operation)) {
                if ("ACTIVE".equals(state)) { verifyDisplay(); verifyLaunchedLocations(snapshot()); }
            } else if ("launch".equals(r.operation)||FixedIntentTools.isTool(r.operation)) {
                guard(r, true);
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
                    intent = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
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
                    BackgroundOwnedTaskPolicy.Plan taskPolicy = BackgroundOwnedTaskPolicy.choose(
                        config.generation, displayId, r.packageName, currentActivity, intent.getFlags());
                    intent.setFlags(taskPolicy.outboundFlags);
                    taskLaunchPolicies.put(r.requestId, taskLaunchPolicyEvidence(r, currentActivity, taskPolicy));
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
                    }
                    finally { effectInFlight = false; }
                }
                boolean observed = false;
                while (SystemClock.elapsedRealtime() < r.deadline - 100) {
                    guard(r, true);
                    TaskSnapshot after = snapshot(); after.requireNoOtherDisplay(r.packageName, displayId);
                    verifyLaunchedLocations(after);
                    if (r.packageName.equals(after.singleVisibleTop(displayId))) { observed = true; break; }
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
            beginCleanup(code(error));
            awaitCleanup(Math.max(1, Math.min(CLEANUP_MS, r.deadline - SystemClock.elapsedRealtime())));
            serve = false;
            return response(r, false, code(error), dispatched);
        }
    }

    private void guard(BrokerProtocol.Request r, boolean active) throws Exception {
        r.checkDeadline(SystemClock.elapsedRealtime(), expires);
        if (closing.get()) throw new BrokerProtocol.Refusal("SESSION_CLOSING");
        requireUnlocked();
        if (active) {
            if (!"ACTIVE".equals(state)) throw new BrokerProtocol.Refusal("SESSION_NOT_ACTIVE");
            verifyDisplay();
        }
    }

    private void requireUnlocked() throws BrokerProtocol.Refusal {
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
        int flags = actual.getFlags(); displayFlags = flags;
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
            for (String name : names) {
                ComponentName child = name == null ? null : ComponentName.unflattenFromString(name);
                if (child != null) packages.add(child.getPackageName());
                else if (BrokerProtocol.packageName(name)) packages.add(name);
                else if (emptyContainer && "unknown".equals(name)) { /* Empty task metadata; never ignore a resolved app package. */ }
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
                if (cleanupStarted.get() && now - cleanupAt >= CLEANUP_MS) {
                    boolean known = cleanupDone.getCount() == 0 && "RELEASED".equals(state);
                    if (!known) state = "CLEANUP_UNKNOWN";
                    printTerminal();
                    // Bound even a stalled cleanup or a client that stops reading the close response.
                    // Process death without confirmed absence is never labeled RELEASED.
                    Runtime.getRuntime().halt(known ? 0 : 70);
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

    private void beginCleanup(String reason) {
        closing.set(true);
        if (!cleanupStarted.compareAndSet(false, true)) return;
        cleanupAt = SystemClock.elapsedRealtime(); terminalReason = reason; state = "CLOSING";
        Thread cleanup = new Thread(() -> {
            boolean releaseCallFailed = false;
            try {
                // Mutating calls and release share one gate. If a Binder call stalls while holding it,
                // the independent watchdog records UNKNOWN and terminates the owning process.
                synchronized (dispatchGate) {
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
                    if (!present) { gone = true; break; }
                    Thread.sleep(25);
                }
                // A release exception can still end in proven absence; the actual absence is decisive.
                state = gone && !createInFlight && !effectInFlight ? "RELEASED" : "CLEANUP_UNKNOWN";
                if (releaseCallFailed && !gone) terminalReason += ":release_api_failed";
            } catch (Throwable error) { state = "CLEANUP_UNKNOWN"; }
            finally { cleanupDone.countDown(); }
        }, "HeptaBackgroundCleanup");
        cleanup.setDaemon(true); cleanup.start();
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
        JSONObject value = new JSONObject().put("version", BrokerProtocol.VERSION)
            .put("request_id", r == null ? JSONObject.NULL : r.requestId).put("generation", config.generation)
            .put("ok", ok).put("state", state).put("display_id", displayId).put("flags", displayFlags)
            .put("width", WIDTH).put("height", HEIGHT).put("density", DENSITY)
            .put("dispatched", dispatched).put("display_name", displayName)
            .put("expires_elapsed_ms", expires).put("capture_secure", false).put("always_unlocked", false)
            .put("ime_policy", "hide")
            .put("display_policy_readback", displayPolicyReadback==null?JSONObject.NULL:new JSONObject(displayPolicyReadback.toString()));
        if (r != null) {value.put("operation", r.operation);
            if(fixedIntentProofs.containsKey(r.requestId))value.put("fixed_intent",fixedIntentProofs.get(r.requestId));
            if(taskLaunchPolicies.containsKey(r.requestId))value.put("task_launch_policy",taskLaunchPolicies.get(r.requestId));
        }
        if (error != null) value.put("error", error);
        if (!terminalReason.isEmpty()) value.put("terminal_reason", terminalReason);
        return value.toString().getBytes(StandardCharsets.UTF_8);
    }
    private void printTerminal() {
        try { System.out.println(new JSONObject().put("schema", "hepta.background-broker-terminal.v1")
            .put("generation", config.generation).put("state", state).put("display_id", displayId)
            .put("reason", terminalReason).put("release_confirmed", "RELEASED".equals(state))); }
        catch (Throwable ignored) { System.err.println("terminal_receipt_unavailable"); }
    }
    private static int fields(Class<?> type, String... names) throws Exception {
        int result = 0; for (String name : names) result |= type.getField(name).getInt(null); return result;
    }
    private static String code(Throwable error) {
        while (error instanceof InvocationTargetException && ((InvocationTargetException) error).getCause() != null)
            error = ((InvocationTargetException) error).getCause();
        if (error instanceof BrokerProtocol.Refusal) return ((BrokerProtocol.Refusal) error).code;
        if (error instanceof SecurityException) return "FRAMEWORK_PERMISSION_DENIED";
        if (error instanceof NoSuchFieldException || error instanceof NoSuchMethodException || error instanceof ClassNotFoundException)
            return "FRAMEWORK_API_UNAVAILABLE";
        if (error instanceof IOException) return "TRANSPORT_IO_ERROR";
        return "FRAMEWORK_OPERATION_FAILED";
    }
}
