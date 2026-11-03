package org.trillionnium.owneropen;

import android.app.Activity;
import android.app.AlertDialog;
import android.view.View;
import android.view.WindowInsets;
import android.view.Gravity;
import android.graphics.drawable.RippleDrawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.Typeface;
import android.graphics.Color;
import android.graphics.Insets;
import android.content.res.Configuration;
import android.content.res.ColorStateList;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.InputFilter;
import android.text.InputType;
import android.text.TextWatcher;
import org.json.JSONObject;
import org.json.JSONException;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.ImageButton;
import android.widget.Toast;
import android.view.WindowManager;
import android.view.WindowInsetsController;
import android.text.TextUtils;
import org.json.JSONArray;
import java.util.LinkedHashMap;
import java.util.Map;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

/** Minimal truthful UI over the owner-open R5 broker wire. */
public final class OwnerOpenShellActivity extends Activity implements OwnerOpenClient.Listener {
    private static final String STATE_SESSION = "owneropen.session";
    private static final String STATE_TASK = "owneropen.task";
    private static final String STATE_TURN = "owneropen.turn";
    private static final String STATE_PROMPT = "owneropen.prompt";
    private static final String STATE_TRANSCRIPT = "owneropen.transcript";
    private static final String STATE_SCROLL = "owneropen.scroll";
    private static final String STATE_UI_TIMELINE = "owneropen.ui.timeline.v44";
    private static final String STATE_DRAFT_SESSION = "owneropen.ui.draft.session";
    private static final String STATE_DRAFT_TASK = "owneropen.ui.draft.task";
    private static final String STATE_DRAFT_REVISION = "owneropen.ui.draft.revision";
    private static final String STATE_DRAFT_SELECTION_START = "owneropen.ui.draft.selection.start";
    private static final String STATE_DRAFT_SELECTION_END = "owneropen.ui.draft.selection.end";
    private static final String STATE_DRAFT_UNBOUND = "owneropen.ui.draft.unbound";
    private static final String STATE_EMERGENCY = "owneropen.emergency";
    private static final String STATE_UI_ROUTE = "owneropen.ui.route.v48";
    private static final String STATE_UI_ROUTE_PARENT = "owneropen.ui.route.parent.v48";
    private static final String STATE_UI_IME = "owneropen.ui.ime.v49";
    private static final String EMERGENCY_PREFS = "owneropen_emergency_intent";
    private static final String LOCAL_ARMED = "armed";
    private static final String LOCAL_UNKNOWN = "stop-state-unknown";
    private static final Object LOCAL_INTENT_LOCK = new Object();
    private static volatile String processIntent;
    // Confirmed single requests outlive Activity rotation. Neither process
    // restart nor recreation submits a saved request. Queues are bounded.
    private static final ExecutorService EMERGENCY_OPERATIONS = finiteExecutor("owner-open-status", 1);
    private static final ExecutorService STOP_OPERATIONS = finiteExecutor("owner-open-stop", 1);
    private static final ExecutorService INTENT_PERSISTENCE = finiteExecutor("owner-open-local-intent", 32);
    private volatile String emergencyOperationId;
    private static final int MAX_PROMPT_CHARS = 65_536;
    private static final int MAX_SAVED_TRANSCRIPT_CHARS = 16_384;
    private static final int MAX_SAVED_UI_CHARS = 48_000;
    private static final int MAX_UI_ENTRIES = 40;
    private final ExecutorService operations = Executors.newSingleThreadExecutor();
    private String sessionId;
    private String taskId;
    private volatile OwnerOpenClientStateCodec.Snapshot identitySnapshot;
    private OwnerOpenClientStateStore identityStore;
    private volatile String storageFailure;
    private volatile String evidenceFailure;
    private volatile boolean readbackRequired;
    private volatile String pendingInspectRequestId;
    // Only a fully validated, correlated cursor-zero terminal readback creates this process-local proof.
    // No Bundle, transcript, acceptance, or unknown cancellation is terminal authority.
    private volatile OwnerOpenTurnEvidence knownTerminalReadback;
    private volatile boolean identityReady;
    private volatile boolean activityStopped;
    private final Object identityPublicationLock = new Object();
    // Host race-fixture seam only; null in production. Never runs under the publication lock.
    private Runnable evidencePublicationProbe;
    private OwnerOpenClient client;
    private volatile String turnId;
    private EditText prompt;
    private TextView transcript;
    private ScrollView scroll;
    private TextView uiControlStatus;
    private LinearLayout uiAdvancedActions;
    private LinearLayout uiFeed;
    private TextView uiEmptyTitle;
    private TextView uiEmptyNote;
    private LinearLayout uiEmptyState;
    private AlertDialog uiToolsDialog;
    private AlertDialog uiDetailsDialog;
    private AlertDialog uiTaskDialog;
    private String uiPendingRoute;
    private boolean uiPendingRouteParent;
    private boolean uiTaskReturnToTools;
    private boolean uiActivityResumed;
    private boolean uiPendingImeRestore;
    private long uiImeRestoreGeneration;
    private boolean uiNight;
    private boolean uiCompact;
    private boolean uiReturnToTools;
    private TextView uiTaskLabel;
    private final OwnerOpenUiEventFormatter uiFormatter = new OwnerOpenUiEventFormatter();
    private final LinkedHashMap<String, TextView> uiMessageViews = new LinkedHashMap<>();
    private final LinkedHashMap<String, OwnerOpenUiEventFormatter.Entry> uiMessages = new LinkedHashMap<>();
    // Composer persistence is independent of identity and emergency-control I/O.
    // Pending UI saves survive Activity recreation, but never create a request.
    private static final ExecutorService UI_DRAFT_IO = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "owner-open-ui-drafts");
        thread.setDaemon(true);
        return thread;
    });
    private final Handler uiDraftHandler = new Handler(Looper.getMainLooper());
    private final Runnable uiDraftSave = this::uiSaveDraftNow;
    private OwnerOpenUiDraftStore.Scope uiDraftScope;
    private volatile OwnerOpenUiDraftStore uiDraftStore;
    private volatile long uiDraftRevision;
    private long uiDraftEditSequence;
    private long uiUnboundExitSavedSequence = Long.MIN_VALUE;
    private int uiUnboundExitSavedStart = Integer.MIN_VALUE, uiUnboundExitSavedEnd = Integer.MIN_VALUE;
    private OwnerOpenUiDraftStore.Scope uiUnboundSavedScope; // UI_DRAFT_IO only
    private long uiUnboundSavedRevision = -1; // UI_DRAFT_IO only
    private boolean uiDraftLoaded;
    private boolean uiDraftProgrammatic;
    private boolean uiDraftWarningShown;
    private String uiSavedDraftSession, uiSavedDraftTask, uiSavedDraftText;
    private long uiSavedDraftRevision = -1;
    private int uiSavedDraftSelectionStart, uiSavedDraftSelectionEnd;
    private boolean uiSavedDraftUnbound;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        uiRememberDraftBundle(state);
        uiRememberNavigation(state);
        client = new OwnerOpenClient(this);
        String persisted = null;
        boolean storageUnknown = false;
        try { persisted = getSharedPreferences(EMERGENCY_PREFS, MODE_PRIVATE).getString(STATE_EMERGENCY, null); }
        catch (RuntimeException error) { storageUnknown = true; }
        synchronized (LOCAL_INTENT_LOCK) {
            String restoredIntent = state == null ? null : state.getString(STATE_EMERGENCY);
            if (processIntent == null || LOCAL_ARMED.equals(processIntent)) {
                boolean freshProcess = processIntent == null;
                String diskIntent = storageUnknown || persisted == null ? LOCAL_UNKNOWN : persisted;
                // An observed persistent Stop outranks a stale UI Bundle, including
                // unknown, initializing, armed, or a different old operation id.
                if (retainedEmergencyIntent(diskIntent)) {
                    processIntent = diskIntent;
                } else if (retainedEmergencyIntent(restoredIntent)) {
                    processIntent = restoredIntent;
                } else if (freshProcess || !LOCAL_ARMED.equals(diskIntent)
                        || (restoredIntent != null && !LOCAL_ARMED.equals(restoredIntent))) {
                    // Saved UI cannot heal unreadable/missing storage or authorize
                    // a new process. Only explicit status-gated initialization can.
                    processIntent = LOCAL_UNKNOWN;
                } else {
                    // Same-process recreation keeps only already committed authority.
                    processIntent = LOCAL_ARMED;
                }
            }
            emergencyOperationId = LOCAL_ARMED.equals(processIntent) ? null
                    : processIntent.startsWith("state-initializing-") ? LOCAL_UNKNOWN : processIntent;
        }
        if (emergencyOperationId != null) client.inhibitLocally();
        setContentView(buildView());
        getWindow().getDecorView().requestApplyInsets();
        if (emergencyOperationId != null) {
            append("local: emergency or unavailable local control state retained; stop delivery and prior effects may be unknown. "
                    + "Only explicit Stop status is available; no automatic resend.");
        }
        append("local: durable identity is loading; normal operations remain held. Stop controls remain independent.");
        if (state != null) {
            transcript.setText(state.getString(STATE_TRANSCRIPT, ""));
            uiRestoreTimeline(state.getString(STATE_UI_TIMELINE, "[]"));
            final int savedScroll = state.getInt(STATE_SCROLL, 0);
            scroll.post(() -> scroll.scrollTo(0, savedScroll));
            // Saved identity and visible history do not authorize re-dispatch.
            // Only explicit user controls may reconnect/inspect. Send always
            // creates a different turn identity.
            append("local: restored UI history; outcome requires explicit Inspect or Reconnect. "
                    + "No saved turn was sent again.");
        }
        final boolean savedUiIdentity = state != null && (state.getString(STATE_SESSION) != null
                || state.getString(STATE_TASK) != null || state.getString(STATE_TURN) != null);
        // Normal worker only: identity reads/fsync must not delay building emergency UI or its sockets.
        // Initialization never connects, starts, retries or publishes a saved request.
        operations.execute(() -> restoreDurableIdentity(savedUiIdentity));
    }

    private static boolean retainedEmergencyIntent(String value) {
        return value != null && !LOCAL_ARMED.equals(value) && !LOCAL_UNKNOWN.equals(value)
                && !value.startsWith("state-initializing-");
    }

    private void restoreDurableIdentity(boolean savedUiIdentity) {
        try {
            java.nio.file.Path files = getFilesDir().toPath();
            if (activityStopped) return;
            identityStore = new OwnerOpenClientStateStore(files);
            java.util.Optional<OwnerOpenClientStateCodec.Snapshot> saved = identityStore.load();
            boolean fresh = !saved.isPresent();
            final OwnerOpenClientStateCodec.Snapshot loaded;
            if (fresh) {
                // A Bundle with an identity but no durable record is an unresolved upgrade/crash,
                // never permission to create a different session behind the user's old history.
                if (savedUiIdentity)
                    throw new IOException("saved UI identity has no durable record; explicit reconciliation required");
                loaded = identityStore.compareAndSet(0,
                        OwnerOpenClientState.identity(id("session"), id("task"), null));
            } else loaded = saved.get();
            if (activityStopped) return;
            runOnUiThread(() -> {
                if (activityStopped || isDestroyed()) return;
                synchronized (identityPublicationLock) {
                    if (activityStopped || isDestroyed()) return;
                    OwnerOpenClientState selected = loaded.state;
                    sessionId = selected.sessionId;
                    taskId = selected.taskId;
                    turnId = selected.turnId;
                    readbackRequired = turnId != null;
                    identitySnapshot = loaded;
                    // Publish readiness last; a cached Bundle cannot overwrite these disk identities.
                    identityReady = true;
                    if (uiControlStatus != null) uiControlStatus.setText(emergencyOperationId == null
                            ? ui("会话已就绪", "Conversation ready")
                            : ui("新任务已暂停", "New tasks paused"));
                    transcript.append(fresh ? "local: new identity committed; use explicit Send or Reconnect. No request was submitted.\n"
                            : "local: restored durable identity; outcome requires explicit Inspect or Reconnect. No saved turn was sent again.\n");
                }
                uiBindDraft(loaded.state.sessionId, loaded.state.taskId);
                uiRestoreNavigationIfReady();
            });
        } catch (IOException | RuntimeException error) {
            storageFailure = error.toString();
            if (!activityStopped) append("local: durable identity unavailable; Send blocked: " + storageFailure);
            runOnUiThread(this::uiRestoreNavigationIfReady);
        }
    }

    private OwnerOpenClientStateCodec.Snapshot verifiedStoredIdentity() throws IOException {
        if (storageFailure != null || identityStore == null || identitySnapshot == null)
            throw new IOException("durable identity is fenced");
        try {
            OwnerOpenClientStateCodec.Snapshot saved = identityStore.load()
                    .orElseThrow(() -> new IOException("committed identity disappeared"));
            if (saved.revision != identitySnapshot.revision
                    || !saved.state.sessionId.equals(identitySnapshot.state.sessionId)
                    || !saved.state.taskId.equals(identitySnapshot.state.taskId)
                    || !java.util.Objects.equals(saved.state.turnId, identitySnapshot.state.turnId)
                    || !java.util.Objects.equals(saved.state.turnRequestSha256, identitySnapshot.state.turnRequestSha256))
                throw new IOException("durable identity changed outside this Activity");
            return saved;
        } catch (IOException | RuntimeException error) {
            storageFailure = error.toString();
            throw new IOException("durable identity unavailable; no dispatch", error);
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        // Keep UI identity/text only; never save the client, socket or broker
        // credential in an Android saved-state Bundle.
        state.putString(STATE_SESSION, sessionId);
        state.putString(STATE_TASK, taskId);
        state.putString(STATE_TURN, turnId);
        uiSaveDraftBundle(state);
        String history = transcript.getText().toString();
        if (history.length() > MAX_SAVED_TRANSCRIPT_CHARS) {
            int start = history.length() - MAX_SAVED_TRANSCRIPT_CHARS;
            if (Character.isLowSurrogate(history.charAt(start))) {
                start++;
            }
            history = "local: restored recent UI history; Inspect retrieves durable evidence.\n"
                    + history.substring(start);
        }
        state.putString(STATE_TRANSCRIPT, history);
        state.putString(STATE_UI_TIMELINE, uiSaveTimeline());
        state.putInt(STATE_SCROLL, scroll.getScrollY());
        uiSaveNavigation(state);
        if (emergencyOperationId != null) state.putString(STATE_EMERGENCY, emergencyOperationId);
    }


    // The presentation is independent from request identity and execution.
    // Theme tokens can follow the system and the verified stock resource baseline.
    private int UI_BG, UI_SURFACE, UI_COMPOSER, UI_TEXT, UI_MUTED;
    private int UI_ACCENT, UI_ACCENT_TEXT, UI_STOP, UI_STOP_SURFACE, UI_BORDER;
    private int UI_USER, UI_USER_TEXT;

    private void uiLoadTheme() {
        uiNight = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
        UI_BG = getColor(R.color.hepta_background);
        UI_SURFACE = getColor(R.color.hepta_surface);
        UI_COMPOSER = getColor(R.color.hepta_composer);
        UI_TEXT = getColor(R.color.hepta_text);
        UI_MUTED = getColor(R.color.hepta_muted);
        UI_BORDER = getColor(R.color.hepta_border);
        UI_ACCENT = getColor(R.color.hepta_accent);
        UI_ACCENT_TEXT = getColor(R.color.hepta_accent_text);
        UI_STOP = getColor(R.color.hepta_stop);
        UI_STOP_SURFACE = getColor(R.color.hepta_stop_surface);
        UI_USER = getColor(R.color.hepta_user);
        UI_USER_TEXT = getColor(R.color.hepta_user_text);
    }

    private int uiSystemAccent() {
        try { return getColor(uiNight ? android.R.color.system_accent1_200
                : android.R.color.system_accent1_600); }
        catch (RuntimeException unavailable) { return UI_ACCENT; }
    }

    private int uiDp(float value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private float uiOemDp(int resource) {
        return getResources().getDimension(resource) / getResources().getDisplayMetrics().density;
    }

    private float uiBodySp() {
        return getResources().getDimension(R.dimen.oem_ui_body_text_size)
                / getResources().getDisplayMetrics().scaledDensity;
    }

    private boolean uiChinese() {
        return "zh".equalsIgnoreCase(getResources().getConfiguration().getLocales().get(0).getLanguage());
    }

    private String ui(String chinese, String english) { return uiChinese() ? chinese : english; }

    private GradientDrawable uiShape(int color, float radiusDp, int strokeColor) {
        GradientDrawable result = new GradientDrawable();
        result.setColor(color);
        result.setCornerRadius(uiDp(radiusDp));
        if (strokeColor != Color.TRANSPARENT) result.setStroke(uiDp(1), strokeColor);
        return result;
    }

    private TextView uiText(String content, float sp, int color, boolean bold) {
        TextView result = new TextView(this);
        result.setText(content);
        result.setTextColor(color);
        result.setTextSize(sp);
        result.setGravity(Gravity.CENTER_VERTICAL);
        result.setTypeface(Typeface.create(bold ? "sans-serif-medium" : "sans-serif", Typeface.NORMAL));
        result.setIncludeFontPadding(false);
        return result;
    }

    private LinearLayout uiColumn() {
        LinearLayout result = new LinearLayout(this);
        result.setOrientation(LinearLayout.VERTICAL);
        return result;
    }

    private LinearLayout uiRow() {
        LinearLayout result = new LinearLayout(this);
        result.setOrientation(LinearLayout.HORIZONTAL);
        result.setGravity(Gravity.CENTER_VERTICAL);
        return result;
    }

    private Button uiAction(String title, boolean primary, boolean danger, View.OnClickListener click) {
        Button button = new Button(this);
        button.setAllCaps(false);
        button.setText(title);
        button.setTextSize(14f);
        button.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        button.setTextColor(danger ? UI_STOP : primary ? UI_ACCENT_TEXT : UI_TEXT);
        int color = danger ? UI_STOP_SURFACE : primary ? uiSystemAccent() : UI_COMPOSER;
        button.setBackground(new RippleDrawable(ColorStateList.valueOf(uiNight ? 0x26FFFFFF : 0x15000000),
                uiShape(color, uiOemDp(R.dimen.oem_ui_control_radius), Color.TRANSPARENT), null));
        button.setMinimumHeight(getResources().getDimensionPixelSize(R.dimen.oem_ui_touch_target));
        button.setMinHeight(getResources().getDimensionPixelSize(R.dimen.oem_ui_touch_target));
        button.setMinimumWidth(0);
        button.setMinWidth(0);
        button.setStateListAnimator(null);
        button.setElevation(0f);
        button.setPadding(uiDp(16), uiDp(10), uiDp(16), uiDp(10));
        button.setOnClickListener(click);
        return button;
    }

    private ImageButton uiIconAction(int drawable, String label, boolean primary, View.OnClickListener click) {
        ImageButton button = new ImageButton(this);
        button.setImageResource(drawable);
        button.setImageTintList(ColorStateList.valueOf(primary ? UI_ACCENT_TEXT : UI_TEXT));
        button.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        int touch = getResources().getDimensionPixelSize(R.dimen.oem_ui_touch_target);
        int icon = getResources().getDimensionPixelSize(R.dimen.oem_ui_icon_size);
        int padding = Math.max(0, (touch - icon) / 2);
        button.setPadding(padding, padding, padding, padding);
        button.setMinimumWidth(touch);
        button.setMinimumHeight(touch);
        button.setStateListAnimator(null);
        button.setElevation(0f);
        button.setBackground(new RippleDrawable(ColorStateList.valueOf(uiNight ? 0x26FFFFFF : 0x15000000),
                uiShape(primary ? uiSystemAccent() : UI_COMPOSER,
                        uiOemDp(R.dimen.oem_ui_control_radius), Color.TRANSPARENT), null));
        button.setContentDescription(label);
        button.setTooltipText(label);
        button.setOnClickListener(click);
        return button;
    }

    private LinearLayout.LayoutParams uiWrap() {
        return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private LinearLayout buildView() {
        uiLoadTheme();
        getWindow().setDecorFitsSystemWindows(false);
        // One inset owner: the root handles navigation, cutouts and IME.
        // adjustNothing prevents the old resize + inset double subtraction.
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_NOTHING);
        getWindow().setStatusBarColor(Color.TRANSPARENT);
        getWindow().setNavigationBarColor(UI_BG);
        getWindow().setNavigationBarContrastEnforced(false);
        WindowInsetsController bars = getWindow().getDecorView().getWindowInsetsController();
        if (bars != null) {
            int appearance = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                    | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
            bars.setSystemBarsAppearance(uiNight ? 0 : appearance, appearance);
        }
        LinearLayout root = uiColumn();
        root.setBackgroundColor(UI_BG);
        final int side = uiDp(16);
        root.setPadding(side, uiDp(8), side, uiDp(8));
        root.setLayoutDirection(View.LAYOUT_DIRECTION_LOCALE);

        LinearLayout top = uiRow();
        top.setMinimumHeight(getResources().getDimensionPixelSize(R.dimen.oem_ui_toolbar_height));
        ImageButton back = uiIconAction(R.drawable.hepta_ic_back,
                ui("返回", "Back"), false, view -> { uiSaveDraftNow(); finish(); });
        back.setBackground(new RippleDrawable(ColorStateList.valueOf(uiNight ? 0x26FFFFFF : 0x15000000),
                uiShape(Color.TRANSPARENT, 24, Color.TRANSPARENT), null));
        top.addView(back, new LinearLayout.LayoutParams(uiDp(48), uiDp(48)));
        LinearLayout titleGroup = uiColumn();
        titleGroup.setPadding(uiDp(4), uiDp(4), uiDp(6), uiDp(4));
        TextView title = uiText("HEPTA", 22f, UI_TEXT, true);
        title.setSingleLine(true);
        title.setEllipsize(TextUtils.TruncateAt.END);
        titleGroup.addView(title);
        uiControlStatus = uiText(ui("正在读取会话", "Loading conversation"), 12f, UI_MUTED, false);
        uiControlStatus.setId(R.id.ui_control_status);
        uiControlStatus.setSingleLine(true);
        uiControlStatus.setEllipsize(TextUtils.TruncateAt.END);
        uiControlStatus.setPadding(0, uiDp(4), 0, 0);
        titleGroup.addView(uiControlStatus);
        top.addView(titleGroup, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        ImageButton tools = uiIconAction(R.drawable.oem_motosystemui_ic_more_vert,
                ui("更多操作", "More actions"), false, view -> uiShowTools());
        tools.setId(R.id.ui_tools);
        top.addView(tools, new LinearLayout.LayoutParams(uiDp(48), ViewGroup.LayoutParams.WRAP_CONTENT));
        Button stop = uiAction(ui("停止", "Stop"), false, true, view -> confirmEmergencyStop());
        stop.setCompoundDrawablesRelativeWithIntrinsicBounds(R.drawable.hepta_ic_stop, 0, 0, 0);
        stop.setCompoundDrawableTintList(ColorStateList.valueOf(UI_STOP));
        stop.setCompoundDrawablePadding(uiDp(5));
        stop.setPadding(uiDp(12), uiDp(8), uiDp(12), uiDp(8));
        stop.setId(R.id.ui_stop);
        stop.setContentDescription(ui("紧急停止 AI 任务", "Emergency stop AI execution"));
        LinearLayout.LayoutParams stopLp = uiWrap();
        stopLp.leftMargin = uiDp(8);
        top.addView(stop, stopLp);
        root.addView(top, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        LinearLayout taskStrip = uiRow();
        taskStrip.setId(R.id.ui_task_summary);
        taskStrip.setPadding(uiDp(14), uiDp(10), uiDp(12), uiDp(10));
        taskStrip.setBackground(new RippleDrawable(ColorStateList.valueOf(uiNight ? 0x26FFFFFF : 0x15000000),
                uiShape(UI_SURFACE, 20, Color.TRANSPARENT), null));
        ImageView taskIcon = new ImageView(this);
        taskIcon.setImageResource(R.drawable.hepta_ic_task);
        taskIcon.setImageTintList(ColorStateList.valueOf(UI_MUTED));
        taskStrip.addView(taskIcon, new LinearLayout.LayoutParams(uiDp(20), uiDp(20)));
        uiTaskLabel = uiText(ui("当前任务", "Current task"), 14f, UI_TEXT, false);
        uiTaskLabel.setPadding(uiDp(10), 0, uiDp(8), 0);
        uiTaskLabel.setSingleLine(true);
        uiTaskLabel.setEllipsize(TextUtils.TruncateAt.END);
        taskStrip.addView(uiTaskLabel, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        ImageView taskChevron = new ImageView(this);
        taskChevron.setImageResource(R.drawable.hepta_ic_chevron);
        taskChevron.setImageTintList(ColorStateList.valueOf(UI_MUTED));
        taskStrip.addView(taskChevron, new LinearLayout.LayoutParams(uiDp(20), uiDp(20)));
        taskStrip.setMinimumHeight(uiDp(48));
        taskStrip.setContentDescription(ui("查看当前任务与操作", "View current task and actions"));
        taskStrip.setOnClickListener(view -> uiShowTask());
        LinearLayout.LayoutParams taskLp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        taskLp.topMargin = uiDp(12);
        taskLp.bottomMargin = uiDp(4);
        root.addView(taskStrip, taskLp);

        FrameLayout content = new FrameLayout(this);
        LinearLayout.LayoutParams contentLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        contentLp.topMargin = uiDp(4);
        root.addView(content, contentLp);
        uiFeed = uiColumn();
        uiFeed.setId(R.id.ui_feed);
        uiFeed.setPadding(uiDp(2), uiDp(12), uiDp(2), uiDp(18));
        scroll = new ScrollView(this);
        scroll.setFillViewport(false);
        scroll.setVerticalScrollBarEnabled(false);
        scroll.setOverScrollMode(View.OVER_SCROLL_IF_CONTENT_SCROLLS);
        scroll.setClipToPadding(false);
        scroll.addView(uiFeed, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        content.addView(scroll, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        uiEmptyState = uiColumn();
        uiEmptyState.setGravity(Gravity.CENTER);
        uiEmptyState.setPadding(uiDp(20), uiDp(16), uiDp(20), uiDp(16));
        ImageView assistantMark = new ImageView(this);
        assistantMark.setImageResource(R.drawable.hepta_ic_conversation);
        assistantMark.setImageTintList(ColorStateList.valueOf(UI_TEXT));
        assistantMark.setPadding(uiDp(16), uiDp(16), uiDp(16), uiDp(16));
        assistantMark.setBackground(uiShape(UI_SURFACE, 24, Color.TRANSPARENT));
        LinearLayout.LayoutParams markLp = new LinearLayout.LayoutParams(uiDp(64), uiDp(64));
        markLp.gravity = Gravity.CENTER_HORIZONTAL;
        markLp.bottomMargin = uiDp(20);
        uiEmptyState.addView(assistantMark, markLp);
        uiEmptyTitle = uiText(ui("有什么需要帮忙？", "How can I help?"), 24f, UI_TEXT, true);
        uiEmptyTitle.setGravity(Gravity.CENTER);
        uiEmptyNote = uiText(ui("提个问题，或交代一个任务。", "Ask a question, or start a task."),
                15f, UI_MUTED, false);
        uiEmptyNote.setGravity(Gravity.CENTER);
        uiEmptyNote.setPadding(0, uiDp(12), 0, 0);
        uiEmptyState.addView(uiEmptyTitle);
        uiEmptyState.addView(uiEmptyNote);
        content.addView(uiEmptyState, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.CENTER));

        // The original transcript remains available on its own details surface.
        transcript = uiText("", 12f, UI_MUTED, false);
        transcript.setTextIsSelectable(true);
        transcript.setTextDirection(View.TEXT_DIRECTION_FIRST_STRONG);

        LinearLayout composer = uiRow();
        composer.setGravity(Gravity.BOTTOM);
        composer.setPadding(uiDp(12), uiDp(7), uiDp(7), uiDp(7));
        composer.setBackground(uiShape(UI_SURFACE, 28, Color.TRANSPARENT));
        LinearLayout.LayoutParams composerLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        composerLp.topMargin = uiDp(6);
        root.addView(composer, composerLp);
        prompt = new EditText(this);
        prompt.setId(R.id.ui_prompt);
        // Manual, conversation-bound restore owns this field; framework view-state must not
        // later replace a newly typed or already restored draft with a stale EditText value.
        prompt.setSaveEnabled(false);
        prompt.setSingleLine(false);
        prompt.setMinLines(1);
        prompt.setMaxLines(4);
        prompt.setHint(ui("发消息或交代任务…", "Message or start a task…"));
        prompt.setHintTextColor(UI_MUTED);
        prompt.setTextColor(UI_TEXT);
        prompt.setTextSize(uiBodySp());
        prompt.setBackgroundColor(Color.TRANSPARENT);
        prompt.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);
        prompt.setImeOptions(android.view.inputmethod.EditorInfo.IME_FLAG_NO_ENTER_ACTION
                | android.view.inputmethod.EditorInfo.IME_FLAG_NO_EXTRACT_UI
                | android.view.inputmethod.EditorInfo.IME_FLAG_NO_FULLSCREEN);
        prompt.setFilters(new InputFilter[] {new InputFilter.LengthFilter(MAX_PROMPT_CHARS)});
        prompt.setPadding(uiDp(4), uiDp(12), uiDp(8), uiDp(12));
        prompt.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence text, int start, int count, int after) {}
            public void onTextChanged(CharSequence text, int start, int before, int count) {}
            public void afterTextChanged(Editable text) {
                if (uiDraftProgrammatic) return;
                uiDraftEditSequence++;
                uiDraftHandler.removeCallbacks(uiDraftSave);
                if (uiDraftLoaded) uiDraftHandler.postDelayed(uiDraftSave, 300);
            }
        });
        composer.addView(prompt, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        ImageButton send = uiIconAction(R.drawable.oem_motoexternaldisplaylauncher_ic_send,
                ui("发送", "Send"), true, view -> sendPrompt());
        send.setId(R.id.ui_send);
        composer.addView(send, new LinearLayout.LayoutParams(uiDp(48),
                ViewGroup.LayoutParams.WRAP_CONTENT));

        final boolean[] compactInput = {false};
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            Insets safe = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            Insets keyboard = insets.getInsets(WindowInsets.Type.ime());
            boolean imeVisible = insets.isVisible(WindowInsets.Type.ime());
            int usableHeight = getWindowManager().getCurrentWindowMetrics().getBounds().height()
                    - safe.top - Math.max(safe.bottom, keyboard.bottom);
            boolean coverSize = getWindowManager().getCurrentWindowMetrics().getBounds().height() < uiDp(560);
            uiCompact = coverSize;
            boolean compact = imeVisible && usableHeight < uiDp(360);
            int horizontal = uiDp(coverSize ? 12 : 16);
            view.setPadding(horizontal + safe.left, safe.top + uiDp(compact ? 4 : 6),
                    horizontal + safe.right, Math.max(safe.bottom, keyboard.bottom) + uiDp(compact ? 4 : 8));
            taskStrip.setVisibility(imeVisible || coverSize ? View.GONE : View.VISIBLE);
            assistantMark.setVisibility(usableHeight < uiDp(430) ? View.GONE : View.VISIBLE);
            uiControlStatus.setVisibility(imeVisible ? View.GONE : View.VISIBLE);
            uiEmptyState.setVisibility(imeVisible || !uiMessages.isEmpty() ? View.GONE : View.VISIBLE);
            if (compact != compactInput[0]) {
                ((ViewGroup) stop.getParent()).removeView(stop);
                if (compact) {
                    top.setVisibility(View.GONE);
                    LinearLayout.LayoutParams compactStopLp = uiWrap();
                    compactStopLp.leftMargin = uiDp(4);
                    composer.addView(stop, compactStopLp);
                    composer.setPadding(uiDp(8), uiDp(4), uiDp(4), uiDp(4));
                } else {
                    top.setVisibility(View.VISIBLE);
                    top.addView(stop, stopLp);
                    composer.setPadding(uiDp(12), uiDp(7), uiDp(7), uiDp(7));
                }
                compactInput[0] = compact;
            }
            prompt.setMaxLines(imeVisible ? (compact ? 1 : 2) : coverSize ? 2 : 4);
            prompt.setPadding(uiDp(4), uiDp(compact ? 5 : 12), uiDp(8), uiDp(compact ? 5 : 12));
            uiRestoreImeIfReady();
            return insets;
        });
        root.addOnLayoutChangeListener((view, l, t, rr, b, oldL, oldT, oldR, oldB) -> {
            int available = content.getHeight();
            if (uiEmptyNote != null) uiEmptyNote.setVisibility(available < uiDp(170)
                    ? View.GONE : View.VISIBLE);
            if (uiEmptyTitle != null) uiEmptyTitle.setTextSize(available < uiDp(220) ? 20f : 24f);
        });
        root.getViewTreeObserver().addOnWindowFocusChangeListener(focused -> {
            if (focused) uiRestoreImeIfReady();
        });
        return root;
    }

    private void uiShowTools() {
        if (isFinishing() || (uiToolsDialog != null && uiToolsDialog.isShowing())) return;
        uiPendingRoute = null;
        uiPendingRouteParent = false;
        uiHideKeyboard();
        LinearLayout actions = uiColumn();
        actions.setPadding(uiDp(8), uiDp(4), uiDp(8), uiDp(8));
        uiAdvancedActions = actions;
        uiToolAction(actions, ui("连接服务", "Connect"), ui("继续当前对话", "Continue this conversation"),
                R.drawable.hepta_ic_connect, R.id.ui_reconnect, this::reconnect);
        uiToolAction(actions, ui("当前任务", "Current task"), ui("查看结果、进度与取消操作", "Result, progress and cancellation"),
                R.drawable.hepta_ic_task, R.id.ui_inspect, () -> uiShowTask(true));
        uiSectionLabel(actions, ui("任务控制", "Task controls"));
        uiToolAction(actions, ui("停止状态", "Stop status"), ui("查看任务是否仍被暂停", "Check whether new tasks are paused"),
                R.drawable.hepta_ic_status, R.id.ui_stop_status, this::emergencyStatus);
        uiToolAction(actions, ui("启用新任务", "Allow new tasks"), ui("确认状态后再恢复新任务", "Review status before enabling"),
                R.drawable.hepta_ic_play, 0, this::confirmInitializeControl);
        uiSectionLabel(actions, ui("更多", "More"));
        uiToolAction(actions, ui("应用权限", "App permissions"), ui("在系统设置中管理 HEPTA", "Manage HEPTA in system settings"),
                R.drawable.hepta_ic_settings, R.id.ui_permissions, this::uiShowPermissions);
        uiToolAction(actions, ui("记录与详情", "Records & details"), ui("查看本机保存的运行记录", "View saved activity records"),
                R.drawable.hepta_ic_history, R.id.ui_details, () -> { uiReturnToTools = true; uiShowDetails(); });
        ScrollView viewport = new ScrollView(this);
        viewport.setVerticalScrollBarEnabled(false);
        viewport.addView(actions);
        uiToolsDialog = new AlertDialog.Builder(this)
                .setCustomTitle(uiDialogHeader(ui("HEPTA", "HEPTA"), false))
                .setView(viewport).setNegativeButton(ui("完成", "Done"), null).create();
        uiToolsDialog.show();
        uiSizeDialog(uiToolsDialog);
    }

    private void uiSectionLabel(LinearLayout parent, String title) {
        TextView label = uiText(title, 12f, UI_MUTED, true);
        label.setPadding(uiDp(16), uiDp(16), uiDp(16), uiDp(6));
        parent.addView(label, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
    }

    private void uiToolAction(LinearLayout parent, String title, String subtitle,
            int icon, int viewId, Runnable action) {
        LinearLayout row = uiRow();
        row.setMinimumHeight(uiDp(64));
        row.setPadding(uiDp(16), uiDp(10), uiDp(12), uiDp(10));
        row.setBackground(new RippleDrawable(ColorStateList.valueOf(uiNight ? 0x26FFFFFF : 0x15000000),
                uiShape(Color.TRANSPARENT, 20, Color.TRANSPARENT), null));
        row.setFocusable(true);
        row.setContentDescription(title + ". " + subtitle);
        row.setOnClickListener(view -> {
            if (uiToolsDialog != null) uiToolsDialog.dismiss();
            action.run();
        });
        if (viewId != 0) row.setId(viewId);
        ImageView glyph = new ImageView(this);
        glyph.setImageResource(icon);
        glyph.setImageTintList(ColorStateList.valueOf(UI_TEXT));
        row.addView(glyph, new LinearLayout.LayoutParams(uiDp(24), uiDp(24)));
        LinearLayout words = uiColumn();
        words.setPadding(uiDp(16), 0, uiDp(10), 0);
        words.addView(uiText(title, 16f, UI_TEXT, false));
        if (subtitle != null && !subtitle.isEmpty()) {
            TextView note = uiText(subtitle, 12f, UI_MUTED, false);
            note.setPadding(0, uiDp(4), 0, 0);
            words.addView(note);
        }
        row.addView(words, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        ImageView chevron = new ImageView(this);
        chevron.setImageResource(R.drawable.hepta_ic_chevron);
        chevron.setImageTintList(ColorStateList.valueOf(UI_MUTED));
        row.addView(chevron, new LinearLayout.LayoutParams(uiDp(20), uiDp(20)));
        parent.addView(row, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
    }

    private void uiShowTask() { uiShowTask(false); }

    private void uiShowTask(boolean returnToTools) {
        if (isFinishing() || isDestroyed() || activityStopped
                || (uiTaskDialog != null && uiTaskDialog.isShowing())) return;
        uiPendingRoute = null;
        uiPendingRouteParent = false;
        uiHideKeyboard();
        LinearLayout actions = uiColumn();
        actions.setPadding(uiDp(8), uiDp(4), uiDp(8), uiDp(8));
        String selected = !identityReady ? ui("会话暂不可用", "Conversation unavailable")
                : turnId == null ? ui("还没有发送任务", "No task sent yet")
                : ui("当前会话中的任务", "Task in this conversation");
        uiSectionLabel(actions, selected);
        uiToolAction(actions, ui("查看任务结果", "View task result"), ui("读取当前任务的实际记录", "Read this task's recorded result"),
                R.drawable.hepta_ic_task, R.id.ui_inspect, this::inspectTurn);
        uiToolAction(actions, ui("取消当前任务", "Cancel current task"), ui("只取消当前任务", "Cancel only the selected task"),
                R.drawable.hepta_ic_stop, R.id.ui_cancel, this::cancelTurn);
        ScrollView viewport = new ScrollView(this);
        viewport.addView(actions);
        AlertDialog taskDialog = new AlertDialog.Builder(this)
                .setCustomTitle(uiDialogHeader(ui("当前任务", "Current task"), false))
                .setView(viewport).setNegativeButton(ui("返回", "Back"), null).create();
        uiTaskDialog = taskDialog;
        uiTaskReturnToTools = returnToTools;
        final boolean[] navigateBack = {returnToTools};
        taskDialog.setOnDismissListener(ignored -> {
            if (navigateBack[0] && !isFinishing() && !activityStopped) uiShowTools();
        });
        // Action rows dismiss their own sheet before invoking the unchanged control path.
        for (int i = 0; i < actions.getChildCount(); i++) {
            View row = actions.getChildAt(i);
            if (row.getId() == R.id.ui_inspect || row.getId() == R.id.ui_cancel) {
                final Runnable operation = row.getId() == R.id.ui_inspect ? this::inspectTurn : this::cancelTurn;
                row.setOnClickListener(view -> { navigateBack[0] = false; taskDialog.dismiss(); operation.run(); });
            }
        }
        taskDialog.show();
        uiSizeDialog(taskDialog);
    }

    private void uiShowPermissions() {
        try {
            startActivity(new android.content.Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    android.net.Uri.parse("package:" + getPackageName())));
        } catch (RuntimeException unavailable) {
            Toast.makeText(this, ui("暂时无法打开系统设置", "System settings unavailable"), Toast.LENGTH_SHORT).show();
        }
    }

    private LinearLayout uiDialogHeader(String label, boolean details) {
        LinearLayout row = uiRow();
        row.setPadding(uiDp(20), uiDp(16), uiDp(16), uiDp(8));
        row.addView(uiText(label, 20f, UI_TEXT, true),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        Button stop = uiAction(ui("停止", "Stop"), false, true, view -> {
            if (uiToolsDialog != null) uiToolsDialog.dismiss();
            uiReturnToTools = false;
            if (uiDetailsDialog != null) uiDetailsDialog.dismiss();
            confirmEmergencyStop();
        });
        stop.setContentDescription(ui("紧急停止 AI 任务", "Emergency stop AI execution"));
        row.addView(stop, uiWrap());
        return row;
    }

    private void uiSizeDialog(AlertDialog dialog) {
        android.graphics.Rect bounds = getWindowManager().getCurrentWindowMetrics().getBounds();
        dialog.getWindow().setBackgroundDrawable(uiShape(UI_SURFACE, 28, Color.TRANSPARENT));
        dialog.getWindow().setLayout(Math.min(bounds.width() - uiDp(24), uiDp(520)),
                Math.min(bounds.height() - uiDp(40), uiDp(uiCompact ? 420 : 620)));
        dialog.getWindow().setGravity(Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        WindowManager.LayoutParams attributes = dialog.getWindow().getAttributes();
        attributes.y = uiDp(12);
        dialog.getWindow().setAttributes(attributes);
        dialog.getWindow().setNavigationBarColor(UI_SURFACE);
        dialog.getWindow().setNavigationBarContrastEnforced(false);
    }

    private void uiHideKeyboard() {
        uiImeRestoreGeneration++;
        uiPendingImeRestore = false;
        WindowInsetsController controller = getWindow().getDecorView().getWindowInsetsController();
        if (controller != null) controller.hide(WindowInsets.Type.ime());
    }

    private void uiShowDetails() {
        if (uiDetailsDialog != null && uiDetailsDialog.isShowing()) return;
        uiPendingRoute = null;
        uiPendingRouteParent = false;
        uiHideKeyboard();
        TextView raw = uiText(transcript.getText().toString(), 12f, UI_TEXT, false);
        raw.setId(R.id.ui_log);
        raw.setTextIsSelectable(true);
        raw.setTypeface(Typeface.MONOSPACE);
        raw.setPadding(uiDp(20), uiDp(8), uiDp(20), uiDp(16));
        ScrollView viewport = new ScrollView(this);
        viewport.addView(raw);
        uiDetailsDialog = new AlertDialog.Builder(this)
                .setCustomTitle(uiDialogHeader(ui("记录与详情", "Records & details"), true))
                .setView(viewport).setNegativeButton(ui("关闭", "Close"), null).create();
        uiDetailsDialog.setOnDismissListener(ignored -> {
            boolean returnToTools = uiReturnToTools;
            uiReturnToTools = false;
            if (returnToTools && !isFinishing() && !activityStopped) uiShowTools();
        });
        uiDetailsDialog.show();
        uiSizeDialog(uiDetailsDialog);
    }

    private void sendPrompt() {
        if (!normalOperationAllowed() || !sendAllowed()) return;
        String value = prompt.getText().toString();
        if (value.isBlank()) {
            append("local: prompt is empty");
            return;
        }
        final OwnerOpenUiDraftStore.Submission submittedDraft = new OwnerOpenUiDraftStore.Submission(
                new OwnerOpenUiDraftStore.Scope(sessionId, taskId), value, uiDraftEditSequence);
        runOperation("turn.start", () -> {
            if (!sendAllowed()) return;
            OwnerOpenClientStateCodec.Snapshot previous = verifiedStoredIdentity();
            String selectedTurn = id("turn");
            String digest = OwnerOpenFrame.turnRequestSha256(sessionId, taskId, selectedTurn, value);
            synchronized (identityPublicationLock) {
                if (identitySnapshot.revision != previous.revision || !sendAllowed()) return;
                requireSameSelectedTurn(identitySnapshot.state, previous.state);
                // Reserve while still S0: no old inspection can clear the prospective S1 hold.
                readbackRequired = true;
                knownTerminalReadback = null;
                pendingInspectRequestId = null;
            }
            final OwnerOpenClientStateCodec.Snapshot committed;
            try {
                committed = identityStore.compareAndSet(previous.revision,
                        previous.state.selectBoundTurnForExplicitSend(selectedTurn, digest));
            } catch (IOException | RuntimeException error) {
                synchronized (identityPublicationLock) { storageFailure = error.toString(); }
                throw new IOException("identity commit failed or unknown; no turn submitted", error);
            }
            synchronized (identityPublicationLock) {
                identitySnapshot = committed;
                turnId = selectedTurn;
                readbackRequired = true;
                pendingInspectRequestId = null;
            }
            // Show exactly what the user submitted after selecting its durable identity.
            // This display record says nothing about delivery and cannot dispatch work.
            append(OwnerOpenUiEventFormatter.userRecord(selectedTurn, value));
            // The exact semantic identity is durable before any new effect-bearing wire write.
            ensureConnected();
            String request = client.startTurn(sessionId, taskId, selectedTurn, value);
            // Existing startTurn returned after its wire write. Clearing the exact click-time
            // composer is UI behavior only; delivery/outcome still require original receipts.
            uiClearSubmittedDraft(submittedDraft);
            append("local request_id=" + request + " turn_id=" + selectedTurn
                    + "; delivery/outcome require receipts, never automatic resend");
        });
    }

    private void cancelTurn() {
        if (!identityReady || storageFailure != null || identitySnapshot == null) {
            append("local: Cancel held until durable identity is ready; independent Stop remains available");
            return;
        }
        final OwnerOpenClientState selected = identitySnapshot.state;
        if (selected.turnId == null) {
            append("local: no turn has been started");
            return;
        }
        runOperation("turn.cancel", () -> {
            OwnerOpenClientState actual = verifiedStoredIdentity().state;
            requireSameSelectedTurn(selected, actual);
            synchronized (identityPublicationLock) {
                OwnerOpenTurnEvidence terminal = knownTerminalReadback;
                if (terminal != null && terminal.completeReadback && terminal.matches(actual)) {
                    append("local: selected turn is already terminal in its complete original readback; no Cancel request sent");
                    return;
                }
            }
            ensureConnected();
            append("local request_id=" + client.cancelTurn(selected.sessionId, selected.taskId, selected.turnId));
        });
    }

    private static void requireSameSelectedTurn(OwnerOpenClientState selected, OwnerOpenClientState actual)
            throws IOException {
        if (!selected.sessionId.equals(actual.sessionId) || !selected.taskId.equals(actual.taskId)
                || !java.util.Objects.equals(selected.turnId, actual.turnId)
                || !java.util.Objects.equals(selected.turnRequestSha256, actual.turnRequestSha256))
            throw new IOException("queued control identity changed; no target substitution");
    }

    private void inspectTurn() {
        if (!identityReady || storageFailure != null || identitySnapshot == null) {
            append("local: Inspect held until durable identity is ready");
            return;
        }
        final OwnerOpenClientState selected = identitySnapshot.state;
        String selectedTurn = selected.turnId;
        if (selectedTurn == null) {
            append("local: no turn has been started");
            return;
        }
        runOperation("turn.inspect", () -> {
            OwnerOpenClientStateCodec.Snapshot saved = verifiedStoredIdentity();
            requireSameSelectedTurn(selected, saved.state);
            if (saved.state.turnRequestSha256 == null) {
                evidenceFailure = "original request digest missing; no fabricated binding";
                append("local: " + evidenceFailure);
                return;
            }
            ensureConnected();
            append("local request_id=" + client.inspectTurn(sessionId, taskId,
                    saved.state.turnId, saved.state.turnRequestSha256, 0,
                    requestId -> { synchronized (identityPublicationLock) {
                        if (activityStopped || !identityReady) throw new IllegalStateException("Inspect owner stopped");
                        pendingInspectRequestId = requestId;
                    } })
                    + "; explicit cursor-zero readback; pagination/cross-epoch resume pending");
        });
    }

    private void reconnect() {
        if (!normalOperationAllowed()) return;
        runOperation("reconnect", () -> {
            synchronized (identityPublicationLock) { pendingInspectRequestId = null; }
            client.connect();
            append("local: reconnected");
        });
    }

    private static ExecutorService finiteExecutor(String name, int capacity) {
        return new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(capacity), task -> {
                    Thread thread = new Thread(task, name);
                    thread.setDaemon(true);
                    return thread;
                }, new ThreadPoolExecutor.AbortPolicy());
    }

    private boolean normalOperationAllowed() {
        if (identityReady && storageFailure == null && emergencyOperationId == null
                && LOCAL_ARMED.equals(processIntent)) return true;
        append("local: identity/control state is loading, inhibited or unavailable; no dispatch. Stop controls remain available.");
        return false;
    }

    private boolean sendAllowed() {
        if (identityReady && storageFailure == null && evidenceFailure == null && !readbackRequired
                && identitySnapshot != null) return true;
        append("local: Send blocked by unavailable identity or unknown receipt; use explicit Inspect. "
                + "A storage failure requires separate reconciliation; no new turn was dispatched.");
        return false;
    }

    private void confirmInitializeControl() {
        OwnerOpenClient previous = null;
        synchronized (LOCAL_INTENT_LOCK) {
            // Rotation may miss the old Activity's callback. Explicit refresh
            // can publish an already committed armed state, with no connect.
            if (LOCAL_ARMED.equals(processIntent) && LOCAL_UNKNOWN.equals(emergencyOperationId)) {
                previous = client;
                client = new OwnerOpenClient(this);
                emergencyOperationId = null;
                uiControlStatus.setText(ui("会话已就绪", "Conversation ready"));
                append("local: explicitly refreshed committed initialization; "
                        + "use Reconnect. No turn was resent.");
            } else if (LOCAL_ARMED.equals(processIntent) && emergencyOperationId == null) {
                // Repeated initialization is a local no-op, never a new request.
                uiControlStatus.setText(ui("会话已就绪", "Conversation ready"));
                append("local: new turns already allowed; use explicit Reconnect. "
                        + "No previous turn was resent.");
                return;
            }
        }
        if (previous != null) { previous.shutdown(); return; }
        if (!LOCAL_UNKNOWN.equals(processIntent)) {
            append("local: initialization cannot clear an emergency intent");
            return;
        }
        new AlertDialog.Builder(this).setTitle(R.string.initialize_control)
                .setMessage(R.string.initialize_confirm)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.initialize_control, (dialog, which) -> initializeControl())
                .show();
    }

    private void initializeControl() {
        final String operation = id("state-probe");
        submitControl(() -> {
            try {
                String reply = client.emergencyControl(operation, false);
                if (!OwnerOpenFrame.controlStatusAllowsInitialization(reply, operation)) {
                    append("local: initialization refused; device inhibit is present or unknown");
                    return;
                }
                final String initializing = id("state-initializing");
                synchronized (LOCAL_INTENT_LOCK) {
                    if (!LOCAL_UNKNOWN.equals(processIntent)) return;
                    processIntent = initializing;
                }
                INTENT_PERSISTENCE.execute(() -> {
                    try {
                        boolean saved = getSharedPreferences(EMERGENCY_PREFS, MODE_PRIVATE)
                                .edit().putString(STATE_EMERGENCY, LOCAL_ARMED).commit();
                        synchronized (LOCAL_INTENT_LOCK) {
                            if (!initializing.equals(processIntent)) return;
                            if (!saved) {
                                processIntent = LOCAL_UNKNOWN;
                                append("local: initialization persistence failed; no dispatch");
                                return;
                            }
                            processIntent = LOCAL_ARMED;
                            runOnUiThread(() -> {
                                OwnerOpenClient previous;
                                synchronized (LOCAL_INTENT_LOCK) {
                                    if (isDestroyed() || !LOCAL_ARMED.equals(processIntent)
                                            || !LOCAL_UNKNOWN.equals(emergencyOperationId)) return;
                                    previous = client;
                                    client = new OwnerOpenClient(this);
                                    emergencyOperationId = null;
                                    uiControlStatus.setText(ui("会话已就绪", "Conversation ready"));
                                    append("local: explicit initialization recorded; new turns allowed. "
                                            + "No previous turn was resent; use explicit Reconnect.");
                                }
                                previous.shutdown();
                            });
                        }
                    } catch (RuntimeException error) {
                        synchronized (LOCAL_INTENT_LOCK) {
                            if (initializing.equals(processIntent)) processIntent = LOCAL_UNKNOWN;
                        }
                        append("local initialization persistence failed; no dispatch: " + error);
                    }
                });
            } catch (Exception error) { append("local initialization unknown; no dispatch: " + error); }
        });
    }

    private void confirmEmergencyStop() {
        new AlertDialog.Builder(this).setTitle(R.string.emergency_stop)
                .setMessage(emergencyOperationId == null ? R.string.emergency_confirm : R.string.emergency_retry_confirm)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.emergency_stop, (dialog, which) -> emergencyStop())
                .show();
    }

    private void emergencyStop() {
        final String selected = id("stop");
        final OwnerOpenClient selectedClient = client;
        synchronized (LOCAL_INTENT_LOCK) {
            processIntent = selected;
            emergencyOperationId = selected;
        }
        selectedClient.inhibitLocally();
        append("local: explicit emergency intent latched; cancellation and prior effects require evidence.");
        // Send once without waiting for SharedPreferences fsync. This process
        // keeps the intent; Bundle and best-effort durable prefs preserve it.
        // Native ingress independently publishes the device-side durable fence.
        submitStop(() -> {
            try { append(selectedClient.emergencyControl(selected, true)); }
            catch (Exception error) { append("local emergency delivery unknown: " + error
                    + "; no automatic resend. Use Stop status or explicitly confirm another mechanical stop."); }
        });
        try {
            INTENT_PERSISTENCE.execute(() -> {
                try {
                    if (!selected.equals(processIntent)) return;
                    boolean saved = getSharedPreferences(EMERGENCY_PREFS, MODE_PRIVATE)
                            .edit().putString(STATE_EMERGENCY, selected).commit();
                    append("local: durable local emergency intent=" + saved
                            + "; storage failure requires explicit coordination.");
                } catch (RuntimeException error) { append("local emergency persistence failed: " + error); }
            });
        } catch (RuntimeException error) { append("local emergency persistence unavailable: " + error); }
    }

    private void emergencyStatus() {
        final String selected = emergencyOperationId;
        final OwnerOpenClient selectedClient = client;
        if (selected == null) { append("local: no local emergency intent"); return; }
        submitControl(() -> {
            try { append(selectedClient.emergencyControl(selected, false)); }
            catch (Exception error) { append("local emergency status unknown: " + error); }
        });
    }

    private void submitStop(Runnable operation) {
        try { STOP_OPERATIONS.execute(operation); }
        catch (RuntimeException error) { append("local stop queue unavailable; delivery unknown: " + error); }
    }

    private void submitControl(Runnable operation) {
        try { EMERGENCY_OPERATIONS.execute(operation); }
        catch (RuntimeException error) { append("local control queue unavailable; outcome unknown: " + error); }
    }

    private void ensureConnected() throws IOException {
        if (!identityReady || activityStopped || storageFailure != null)
            throw new IOException("identity unavailable; no normal connection");
        if (emergencyOperationId != null || !LOCAL_ARMED.equals(processIntent)) throw new IOException("emergency inhibit; status only");
        if (!client.isConnected()) {
            client.connect();
        }
    }

    private void runOperation(String label, CheckedOperation operation) {
        operations.execute(() -> {
            try {
                if (!identityReady || activityStopped || storageFailure != null)
                    throw new IOException("identity unavailable; normal operation held");
                if (emergencyOperationId != null || !LOCAL_ARMED.equals(processIntent)) throw new IOException("emergency inhibit; status only");
                operation.run();
            } catch (Exception error) {
                append("local " + label + " failed: " + error);
            }
        });
    }

    @Override
    public void onFrame(String rawJsonLine) {
        if (activityStopped) return;
        OwnerOpenTurnEvidence displayEvidence = null;
        try {
            OwnerOpenTurnEvidence evidence = OwnerOpenTurnEvidence.parse(rawJsonLine);
            if (evidence != null) {
                Runnable probe = evidencePublicationProbe;
                if (probe != null) probe.run();
                synchronized (identityPublicationLock) {
                    if (activityStopped) return;
                    OwnerOpenClientStateCodec.Snapshot selected = identitySnapshot;
                    if ("turn.inspect.result".equals(evidence.kind)
                            && !evidence.brokerRequestId.equals(pendingInspectRequestId)) {
                        append("local: stale or unrequested inspection cannot release Send hold");
                        uiAppendWire(rawJsonLine, null);
                        return;
                    }
                    if (selected == null || !evidence.matches(selected.state))
                        throw new IllegalArgumentException("receipt does not match durable session/task/turn/request digest");
                    if ("turn.inspect.result".equals(evidence.kind)) {
                        pendingInspectRequestId = null;
                        if (evidence.completeReadback) {
                            evidenceFailure = null;
                            readbackRequired = false;
                            knownTerminalReadback = evidence;
                            append("local: original turn records read back in full; effect outcomes remain the records' own evidence. "
                                    + "Only a new explicit Send can select another turn.");
                        } else {
                            knownTerminalReadback = null;
                            readbackRequired = true;
                            append("local: inspection incomplete, absent, unknown or paginated; Send remains held. "
                                    + "No saved cursor or producer epoch was invented.");
                        }
                    } else {
                        append("local: acceptance matches durable request identity; Send remains held until explicit terminal readback");
                    }
                    displayEvidence = evidence;
                }
            }
        } catch (RuntimeException error) {
            synchronized (identityPublicationLock) {
                evidenceFailure = error.toString();
                knownTerminalReadback = null;
                readbackRequired = true;
            }
            append("local: invalid or conflicting readback; Send held, no automatic resend: " + error);
        }
        uiAppendWire(rawJsonLine, displayEvidence);
    }

    @Override
    public void onDisconnected(String reason) {
        synchronized (identityPublicationLock) {
            pendingInspectRequestId = null;
            if (turnId != null) readbackRequired = true;
        }
        append("local disconnected: " + reason);
        runOnUiThread(() -> {
            if (uiControlStatus != null)
                uiControlStatus.setText(ui("连接已断开", "Disconnected"));
        });
    }

    private void append(String value) {
        runOnUiThread(() -> {
            if (activityStopped || isDestroyed()) return;
            uiAppendLog(value);
            if (value != null && (value.startsWith("local: durable identity is loading;")
                    || value.startsWith("local: emergency or unavailable local control state retained;"))) return;
            for (OwnerOpenUiEventFormatter.Entry entry : uiFormatter.accept(value, uiChinese(), null))
                uiApplyEntry(entry, true);
            if (emergencyOperationId != null)
                uiControlStatus.setText(ui("新任务已暂停", "New tasks paused"));
        });
    }

    private void uiAppendWire(String value, OwnerOpenTurnEvidence verifiedEvidence) {
        OwnerOpenClientStateCodec.Snapshot selected = identitySnapshot;
        runOnUiThread(() -> {
            if (activityStopped || isDestroyed()) return;
            uiAppendLog(value);
            for (OwnerOpenUiEventFormatter.Entry entry :
                    uiFormatter.acceptWire(value, uiChinese(), verifiedEvidence,
                            selected == null ? null : selected.state))
                uiApplyEntry(entry, true);
        });
    }

    private void uiAppendLog(String value) {
        if (value == null) return;
        transcript.append(value + "\n");
        // This is a view cache; original execution records remain at their source.
        if (transcript.length() > 131_072) {
            String text = transcript.getText().toString();
            int start = text.length() - 98_304;
            if (Character.isLowSurrogate(text.charAt(start))) start++;
            transcript.setText(text.substring(start));
        }
    }

    private String uiSaveTimeline() {
        JSONArray result = new JSONArray();
        java.util.ArrayList<OwnerOpenUiEventFormatter.Entry> entries =
                new java.util.ArrayList<>(uiMessages.values());
        java.util.ArrayList<JSONObject> kept = new java.util.ArrayList<>();
        int remaining = MAX_SAVED_UI_CHARS;
        for (int i = entries.size() - 1; i >= 0 && kept.size() < MAX_UI_ENTRIES && remaining > 0; i--) {
            OwnerOpenUiEventFormatter.Entry entry = entries.get(i);
            String text = entry.text;
            if (text.length() > remaining) {
                int end = remaining;
                if (end > 0 && Character.isHighSurrogate(text.charAt(end - 1))) end--;
                text = text.substring(0, end);
            }
            if (text.isEmpty()) break;
            try {
                kept.add(new JSONObject().put("key", entry.key).put("role", entry.role.name())
                        .put("text", text));
                remaining -= text.length();
            } catch (JSONException ignored) { break; }
        }
        for (int i = kept.size() - 1; i >= 0; i--) result.put(kept.get(i));
        return result.toString();
    }

    private void uiRestoreTimeline(String saved) {
        if (uiFeed == null || saved == null || saved.length() > MAX_SAVED_UI_CHARS * 6 + 24_576) return;
        try {
            JSONArray entries = new JSONArray(saved);
            int remaining = MAX_SAVED_UI_CHARS;
            for (int i = Math.max(0, entries.length() - MAX_UI_ENTRIES); i < entries.length(); i++) {
                JSONObject item = entries.getJSONObject(i);
                String key = item.getString("key");
                String text = item.getString("text");
                if (key.length() > 384 || text.isEmpty() || text.length() > remaining) continue;
                OwnerOpenUiEventFormatter.Role role = OwnerOpenUiEventFormatter.Role.valueOf(item.getString("role"));
                remaining -= text.length();
                // Restored display text cannot create current execution authority.
                uiApplyEntry(new OwnerOpenUiEventFormatter.Entry(key, role, text, false, true), false);
            }
        } catch (JSONException | IllegalArgumentException ignored) {
            // Damaged display cache is optional; durable identity follows its own path.
        }
    }

    private boolean uiAtBottom() {
        return uiFeed.getHeight() - (scroll.getScrollY() + scroll.getHeight()) <= uiDp(72);
    }

    private void uiApplyEntry(OwnerOpenUiEventFormatter.Entry entry, boolean mayScroll) {
        if (uiFeed == null || entry == null || entry.text.isEmpty()) return;
        boolean fromUser = entry.role == OwnerOpenUiEventFormatter.Role.USER;
        boolean tool = entry.role == OwnerOpenUiEventFormatter.Role.TOOL;
        boolean status = entry.role == OwnerOpenUiEventFormatter.Role.STATUS
                || entry.role == OwnerOpenUiEventFormatter.Role.ERROR;
        boolean follow = mayScroll && (fromUser || uiAtBottom());
        uiEmptyState.setVisibility(View.GONE);
        TextView item = uiMessageViews.get(entry.key);
        if (item == null) {
            item = uiText("", status ? 13f : tool ? 15f : uiBodySp(),
                    entry.role == OwnerOpenUiEventFormatter.Role.ERROR ? UI_STOP
                            : fromUser ? UI_USER_TEXT : status ? UI_MUTED : UI_TEXT, false);
            item.setTextDirection(View.TEXT_DIRECTION_FIRST_STRONG);
            item.setLineSpacing(uiDp(status ? 2 : 4), 1f);
            item.setTextIsSelectable(!status);
            if (tool) item.setTypeface(Typeface.MONOSPACE);
            item.setPadding(uiDp(fromUser || tool ? 16 : 4), uiDp(status ? 4 : 12),
                    uiDp(fromUser || tool ? 16 : 4), uiDp(status ? 4 : 12));
            if (fromUser || tool) item.setBackground(uiShape(fromUser ? UI_USER : UI_SURFACE,
                    uiOemDp(R.dimen.oem_ui_card_radius), tool ? UI_BORDER : Color.TRANSPARENT));
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                    fromUser || status ? ViewGroup.LayoutParams.WRAP_CONTENT : ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT);
            params.gravity = fromUser ? Gravity.END : Gravity.START;
            params.topMargin = uiDp(status ? 5 : 12);
            uiFeed.addView(item, params);
            uiMessageViews.put(entry.key, item);
            if (fromUser) {
                final TextView bubble = item;
                uiFeed.post(() -> bubble.setMaxWidth(Math.max(uiDp(96),
                        (int) ((uiFeed.getWidth() - uiFeed.getPaddingLeft() - uiFeed.getPaddingRight()) * .88f))));
            }
        }
        item.setText(entry.role == OwnerOpenUiEventFormatter.Role.ASSISTANT
                ? OwnerOpenUiMarkdownRenderer.render(entry.text, UI_COMPOSER, UI_MUTED,
                        getResources().getDisplayMetrics().density)
                : entry.text);
        item.setTextColor(entry.role == OwnerOpenUiEventFormatter.Role.ERROR ? UI_STOP
                : fromUser ? UI_USER_TEXT : status ? UI_MUTED : UI_TEXT);
        item.setStateDescription(entry.historical ? ui("已保存的对话", "Saved conversation") : null);
        uiMessages.put(entry.key, entry);
        int total = 0;
        for (OwnerOpenUiEventFormatter.Entry current : uiMessages.values()) total += current.text.length();
        while (uiMessages.size() > MAX_UI_ENTRIES || (total > 131_072 && uiMessages.size() > 1)) {
            String first = uiMessages.keySet().iterator().next();
            total -= uiMessages.remove(first).text.length();
            uiFeed.removeView(uiMessageViews.remove(first));
        }
        if (follow) scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN));
    }

    private static String id(String prefix) {
        return prefix + "-" + UUID.randomUUID();
    }

    private void uiRememberDraftBundle(Bundle state) {
        if (state == null || !state.containsKey(STATE_PROMPT)) return;
        String text = state.getString(STATE_PROMPT, "");
        if (text == null || text.length() > MAX_PROMPT_CHARS) return;
        uiSavedDraftText = text;
        uiSavedDraftSession = state.containsKey(STATE_DRAFT_SESSION)
                ? state.getString(STATE_DRAFT_SESSION) : state.getString(STATE_SESSION);
        uiSavedDraftTask = state.containsKey(STATE_DRAFT_TASK)
                ? state.getString(STATE_DRAFT_TASK) : state.getString(STATE_TASK);
        uiSavedDraftRevision = state.getLong(STATE_DRAFT_REVISION, -1);
        uiSavedDraftSelectionStart = state.getInt(STATE_DRAFT_SELECTION_START, text.length());
        uiSavedDraftSelectionEnd = state.getInt(STATE_DRAFT_SELECTION_END, text.length());
        uiSavedDraftUnbound = state.getBoolean(STATE_DRAFT_UNBOUND, false);
    }

    private void uiSaveDraftBundle(Bundle state) {
        String text = prompt.getText().toString();
        String session = uiDraftScope == null ? null : uiDraftScope.sessionId;
        String task = uiDraftScope == null ? null : uiDraftScope.taskId;
        long revision = uiDraftLoaded ? uiDraftRevision : -1;
        int start = prompt.getSelectionStart(), end = prompt.getSelectionEnd();
        boolean unbound = uiDraftScope == null;
        // Repeated recreation while disk identity is loading also retains the pending UI
        // candidate with its original scope; it is not silently rebound to another session.
        if (!uiDraftLoaded && uiDraftEditSequence == 0 && uiSavedDraftText != null) {
            text = uiSavedDraftText;
            session = uiSavedDraftSession;
            task = uiSavedDraftTask;
            revision = uiSavedDraftRevision;
            start = uiSavedDraftSelectionStart;
            end = uiSavedDraftSelectionEnd;
            unbound = uiSavedDraftUnbound;
        }
        state.putString(STATE_PROMPT, text);
        state.putString(STATE_DRAFT_SESSION, session);
        state.putString(STATE_DRAFT_TASK, task);
        state.putLong(STATE_DRAFT_REVISION, revision);
        state.putInt(STATE_DRAFT_SELECTION_START, start);
        state.putInt(STATE_DRAFT_SELECTION_END, end);
        state.putBoolean(STATE_DRAFT_UNBOUND, unbound);
    }

    private void uiBindDraft(String session, String task) {
        if (uiDraftScope != null) return;
        final OwnerOpenUiDraftStore.Scope scope = new OwnerOpenUiDraftStore.Scope(session, task);
        uiDraftScope = scope;
        final java.nio.file.Path files = getFilesDir().toPath();
        UI_DRAFT_IO.execute(() -> {
            try {
                OwnerOpenUiDraftStore store = new OwnerOpenUiDraftStore(files);
                final OwnerOpenUiDraftStore.Draft saved = store.load(scope).orElse(null);
                // Publish UI-only disk state on the same I/O queue. A final onPause write
                // queued while this read was pending can then preserve newly typed text,
                // even if its Activity has already been destroyed before the UI callback.
                uiDraftStore = store;
                uiDraftRevision = saved == null ? 0 : saved.revision;
                runOnUiThread(() -> {
                    if (activityStopped || isDestroyed() || !scope.equals(uiDraftScope)) return;
                    if (uiDraftEditSequence == 0) {
                        boolean bundleScope = uiSavedDraftText != null
                                && ((scope.sessionId.equals(uiSavedDraftSession) && scope.taskId.equals(uiSavedDraftTask))
                                    || (uiSavedDraftUnbound && uiSavedDraftSession == null && uiSavedDraftTask == null));
                        boolean bundleCurrent = bundleScope && (saved == null
                                || uiSavedDraftRevision >= saved.revision || uiSavedDraftText.equals(saved.text));
                        if (bundleCurrent) uiSetDraftText(uiSavedDraftText,
                                uiSavedDraftSelectionStart, uiSavedDraftSelectionEnd);
                        else if (saved != null) uiSetDraftText(saved.text, saved.selectionStart, saved.selectionEnd);
                    }
                    uiDraftLoaded = true;
                    // Any text entered while the identity/file was loading wins over the cache.
                    // An empty record is retained as a revision so stale Bundles cannot resurrect it.
                    uiSaveDraftNow();
                    uiRestoreImeIfReady();
                });
            } catch (IOException | RuntimeException error) { uiDraftWarning(error); }
        });
    }

    private void uiSetDraftText(String text, int start, int end) {
        uiDraftProgrammatic = true;
        try {
            prompt.setText(text);
            prompt.setSelection(OwnerOpenUiDraftStore.safeSelection(text, start),
                    OwnerOpenUiDraftStore.safeSelection(text, end));
        } finally { uiDraftProgrammatic = false; }
    }

    private void uiSaveDraftNow() {
        uiDraftHandler.removeCallbacks(uiDraftSave);
        if (prompt == null) return;
        if (uiDraftScope == null) { uiSaveUnboundDraftOnExit(); return; }
        if (!uiDraftLoaded && uiDraftEditSequence == 0) return;
        final OwnerOpenUiDraftStore.Scope scope = uiDraftScope;
        final String text = prompt.getText().toString();
        final int start = prompt.getSelectionStart(), end = prompt.getSelectionEnd();
        // The dedicated process queue also orders a finishing Activity's final write before
        // the next Activity's load. Saving does not wait for or cancel any execution work.
        UI_DRAFT_IO.execute(() -> {
            try {
                OwnerOpenUiDraftStore store = uiDraftStore;
                if (store == null) throw new IOException("UI draft load has not completed");
                uiDraftRevision = store.save(scope, uiDraftRevision, text, start, end).revision;
            }
            catch (IOException | RuntimeException error) { uiDraftWarning(error); }
        });
    }

    private void uiSaveUnboundDraftOnExit() {
        if (uiDraftEditSequence == 0 && uiSavedDraftText == null) return;
        final String text = uiDraftEditSequence == 0 ? uiSavedDraftText : prompt.getText().toString();
        final int start = uiDraftEditSequence == 0 ? uiSavedDraftSelectionStart : prompt.getSelectionStart();
        final int end = uiDraftEditSequence == 0 ? uiSavedDraftSelectionEnd : prompt.getSelectionEnd();
        if (uiUnboundExitSavedSequence == uiDraftEditSequence
                && uiUnboundExitSavedStart == start && uiUnboundExitSavedEnd == end) return;
        final boolean fromBundle = uiDraftEditSequence == 0;
        final long bundleRevision = uiSavedDraftRevision;
        final String savedSession = uiDraftEditSequence == 0 ? uiSavedDraftSession : null;
        final String savedTask = uiDraftEditSequence == 0 ? uiSavedDraftTask : null;
        final java.nio.file.Path files = getFilesDir().toPath();
        uiUnboundExitSavedSequence = uiDraftEditSequence;
        uiUnboundExitSavedStart = start;
        uiUnboundExitSavedEnd = end;
        // Back may finish an Activity without onSaveInstanceState. Queue this final new
        // input before the next Activity's UI load, without waiting on the identity worker.
        // The snapshot is only a draft filename hint; it cannot set identityReady or Send.
        UI_DRAFT_IO.execute(() -> {
            try {
                OwnerOpenUiDraftStore.Scope hint = OwnerOpenUiDraftStore.readScopeHint(files);
                if ((savedSession != null || savedTask != null)
                        && (!hint.sessionId.equals(savedSession) || !hint.taskId.equals(savedTask))) return;
                OwnerOpenUiDraftStore store = new OwnerOpenUiDraftStore(files);
                OwnerOpenUiDraftStore.Draft disk = store.load(hint).orElse(null);
                long revision = disk == null ? 0 : disk.revision;
                if (uiUnboundSavedScope == null) {
                    uiUnboundSavedScope = hint;
                    uiUnboundSavedRevision = revision;
                }
                if (!hint.equals(uiUnboundSavedScope) || revision != uiUnboundSavedRevision)
                    throw new IOException("closing UI draft changed in another Activity");
                // A late close of a restored Bundle must not resurrect an already cleared
                // or newer disk draft. User input entered in this Activity remains newer UI.
                if (fromBundle && disk != null && bundleRevision < disk.revision && !text.equals(disk.text)) return;
                uiUnboundSavedRevision = store.save(hint, uiUnboundSavedRevision, text, start, end).revision;
            } catch (IOException | RuntimeException error) { uiDraftWarning(error); }
        });
    }

    private void uiClearSubmittedDraft(OwnerOpenUiDraftStore.Submission submitted) {
        runOnUiThread(() -> {
            if (activityStopped || isDestroyed() || prompt == null
                    || !submitted.stillMatches(uiDraftScope, prompt.getText().toString(), uiDraftEditSequence)) return;
            uiSetDraftText("", 0, 0);
            uiDraftEditSequence++;
            uiSaveDraftNow();
        });
    }

    private void uiDraftWarning(Exception error) {
        runOnUiThread(() -> {
            if (activityStopped || isDestroyed() || uiDraftWarningShown) return;
            uiDraftWarningShown = true;
            uiAppendLog("local UI draft persistence unavailable; visible input retained: " + error);
            Toast.makeText(this, ui("草稿未能保存，当前输入仍保留在窗口中。",
                    "Draft could not be saved. Your current input remains in this window."), Toast.LENGTH_LONG).show();
        });
    }

    @Override
    protected void onNewIntent(android.content.Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        // A cover/launcher entry changes presentation only. No intent extra can send,
        // reconnect, reset a Stop or replace a durable conversation identity.
        getWindow().getDecorView().requestApplyInsets();
    }

    // Only a presentation route survives a fold, resize or Activity recreation.
    // Restoring a sheet never invokes its inspect/cancel/connect/send controls.
    private void uiRememberNavigation(Bundle state) {
        if (state == null) return;
        uiPendingImeRestore = state.getBoolean(STATE_UI_IME, false);
        String route = state.getString(STATE_UI_ROUTE);
        if ("tools".equals(route) || "task".equals(route) || "details".equals(route)) {
            uiPendingRoute = route;
            uiPendingRouteParent = state.getBoolean(STATE_UI_ROUTE_PARENT, false);
        }
    }

    private void uiSaveNavigation(Bundle state) {
        String route = uiPendingRoute;
        boolean parent = uiPendingRouteParent;
        if (uiDetailsDialog != null && uiDetailsDialog.isShowing()) {
            route = "details";
            parent = uiReturnToTools;
        } else if (uiTaskDialog != null && uiTaskDialog.isShowing()) {
            route = "task";
            parent = uiTaskReturnToTools;
        } else if (uiToolsDialog != null && uiToolsDialog.isShowing()) {
            route = "tools";
            parent = false;
        }
        state.remove(STATE_UI_ROUTE);
        state.remove(STATE_UI_ROUTE_PARENT);
        if (route != null) {
            state.putString(STATE_UI_ROUTE, route);
            state.putBoolean(STATE_UI_ROUTE_PARENT, parent);
        }
        WindowInsets insets = getWindow().getDecorView().getRootWindowInsets();
        boolean composing = route == null && prompt != null && prompt.hasFocus()
                && insets != null && insets.isVisible(WindowInsets.Type.ime());
        state.putBoolean(STATE_UI_IME, route == null && (uiPendingImeRestore || composing));
    }

    private void uiRestoreNavigationIfReady() {
        if (uiPendingRoute == null || !uiActivityResumed || activityStopped
                || isFinishing() || isDestroyed()) return;
        // The task heading must reflect the durable identity, never a saved UI hint.
        if ("task".equals(uiPendingRoute) && !identityReady && storageFailure == null) return;
        String route = uiPendingRoute;
        boolean parent = uiPendingRouteParent;
        uiPendingRoute = null;
        uiPendingRouteParent = false;
        if ("tools".equals(route)) uiShowTools();
        else if ("task".equals(route)) uiShowTask(parent);
        else if ("details".equals(route)) {
            uiReturnToTools = parent;
            uiShowDetails();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        uiActivityResumed = true;
        getWindow().getDecorView().post(() -> {
            uiRestoreNavigationIfReady();
            uiRestoreImeIfReady();
        });
    }

    private void uiRestoreImeIfReady() {
        if (!uiPendingImeRestore || !uiActivityResumed || !uiDraftLoaded || activityStopped
                || isFinishing() || isDestroyed() || prompt == null
                || !getWindow().getDecorView().hasWindowFocus()
                || uiPendingRoute != null || uiSheetShowing()) return;
        uiPendingImeRestore = false;
        prompt.requestFocus();
        final long generation = uiImeRestoreGeneration;
        // Wait for the new display's input connection; never open an IME on cold launch.
        prompt.post(() -> {
            if (generation != uiImeRestoreGeneration || !uiActivityResumed
                    || activityStopped || isFinishing() || isDestroyed()
                    || !prompt.hasFocus() || !getWindow().getDecorView().hasWindowFocus()
                    || uiSheetShowing()) return;
            WindowInsetsController controller = getWindow().getDecorView().getWindowInsetsController();
            if (controller != null) controller.show(WindowInsets.Type.ime());
        });
    }

    private boolean uiSheetShowing() {
        return (uiToolsDialog != null && uiToolsDialog.isShowing())
                || (uiTaskDialog != null && uiTaskDialog.isShowing())
                || (uiDetailsDialog != null && uiDetailsDialog.isShowing());
    }

    @Override
    protected void onPause() {
        uiImeRestoreGeneration++;
        uiActivityResumed = false;
        uiSaveDraftNow();
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        uiImeRestoreGeneration++;
        uiSaveDraftNow();
        synchronized (identityPublicationLock) {
            activityStopped = true;
            identityReady = false;
            knownTerminalReadback = null;
            pendingInspectRequestId = null;
        }
        if (uiToolsDialog != null) uiToolsDialog.dismiss();
        if (uiDetailsDialog != null) uiDetailsDialog.dismiss();
        if (uiTaskDialog != null) uiTaskDialog.dismiss();
        client.shutdown();
        operations.shutdownNow();
        super.onDestroy();
    }

    @FunctionalInterface
    private interface CheckedOperation {
        void run() throws Exception;
    }
}
