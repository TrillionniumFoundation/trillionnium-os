package org.trillionnium.owneropen;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.InputFilter;
import android.text.InputType;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

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
    private static final String STATE_EMERGENCY = "owneropen.emergency";
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
    private final ExecutorService operations = Executors.newSingleThreadExecutor();
    private String sessionId;
    private String taskId;
    private volatile OwnerOpenClientStateCodec.Snapshot identitySnapshot;
    private OwnerOpenClientStateStore identityStore;
    private volatile String storageFailure;
    private volatile String evidenceFailure;
    private volatile boolean readbackRequired;
    private volatile String pendingInspectRequestId;
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

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        client = new OwnerOpenClient(this);
        String persisted = null;
        boolean storageUnknown = false;
        try { persisted = getSharedPreferences(EMERGENCY_PREFS, MODE_PRIVATE).getString(STATE_EMERGENCY, null); }
        catch (RuntimeException error) { storageUnknown = true; }
        synchronized (LOCAL_INTENT_LOCK) {
            String restoredIntent = state == null ? null : state.getString(STATE_EMERGENCY);
            if (processIntent == null || LOCAL_ARMED.equals(processIntent)) {
                processIntent = storageUnknown || persisted == null ? LOCAL_UNKNOWN : persisted;
                if (restoredIntent != null) processIntent = restoredIntent;
            }
            emergencyOperationId = LOCAL_ARMED.equals(processIntent) ? null
                    : processIntent.startsWith("state-initializing-") ? LOCAL_UNKNOWN : processIntent;
        }
        if (emergencyOperationId != null) client.inhibitLocally();
        setContentView(buildView());
        if (emergencyOperationId != null) {
            append("local: emergency or unavailable local control state retained; stop delivery and prior effects may be unknown. "
                    + "Only explicit Stop status is available; no automatic resend.");
        }
        append("local: durable identity is loading; normal operations remain held. Stop controls remain independent.");
        if (state != null) {
            prompt.setText(state.getString(STATE_PROMPT, ""));
            transcript.setText(state.getString(STATE_TRANSCRIPT, ""));
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
                    transcript.append(fresh ? "local: new identity committed; use explicit Send or Reconnect. No request was submitted.\n"
                            : "local: restored durable identity; outcome requires explicit Inspect or Reconnect. No saved turn was sent again.\n");
                }
            });
        } catch (IOException | RuntimeException error) {
            storageFailure = error.toString();
            if (!activityStopped) append("local: durable identity unavailable; Send blocked: " + storageFailure);
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
        state.putString(STATE_PROMPT, prompt.getText().toString());
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
        state.putInt(STATE_SCROLL, scroll.getScrollY());
        if (emergencyOperationId != null) state.putString(STATE_EMERGENCY, emergencyOperationId);
    }

    private LinearLayout buildView() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int padding = Math.round(16 * getResources().getDisplayMetrics().density);
        root.setPadding(padding, padding, padding, padding);

        prompt = new EditText(this);
        prompt.setHint(R.string.prompt_hint);
        prompt.setMinLines(3);
        prompt.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        prompt.setFilters(new InputFilter[] {new InputFilter.LengthFilter(MAX_PROMPT_CHARS)});
        root.addView(prompt, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        LinearLayout controls = new LinearLayout(this);
        controls.setOrientation(LinearLayout.HORIZONTAL);
        Button send = button(R.string.send, view -> sendPrompt());
        Button cancel = button(R.string.cancel, view -> cancelTurn());
        Button inspect = button(R.string.inspect, view -> inspectTurn());
        Button reconnect = button(R.string.reconnect, view -> reconnect());
        controls.addView(send);
        controls.addView(cancel);
        controls.addView(inspect);
        controls.addView(reconnect);
        root.addView(controls, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        Button initialize = button(R.string.initialize_control, view -> confirmInitializeControl());
        initialize.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(initialize);
        Button emergency = button(R.string.emergency_stop, view -> confirmEmergencyStop());
        emergency.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(emergency);
        Button status = button(R.string.emergency_status, view -> emergencyStatus());
        status.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(status);

        transcript = new TextView(this);
        transcript.setTextIsSelectable(true);
        scroll = new ScrollView(this);
        scroll.addView(transcript, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        return root;
    }

    private Button button(int label, android.view.View.OnClickListener action) {
        Button result = new Button(this);
        result.setText(label);
        result.setOnClickListener(action);
        result.setAllCaps(false);
        result.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        return result;
    }

    private void sendPrompt() {
        if (!normalOperationAllowed() || !sendAllowed()) return;
        String value = prompt.getText().toString();
        if (value.isBlank()) {
            append("local: prompt is empty");
            return;
        }
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
            // The exact semantic identity is durable before any new effect-bearing wire write.
            ensureConnected();
            String request = client.startTurn(sessionId, taskId, selectedTurn, value);
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
                transcript.append("local: explicitly refreshed committed initialization; "
                        + "use Reconnect. No turn was resent.\n");
            } else if (LOCAL_ARMED.equals(processIntent) && emergencyOperationId == null) {
                // Repeated initialization is a local no-op, never a new request.
                transcript.append("local: new turns already allowed; use explicit Reconnect. "
                        + "No previous turn was resent.\n");
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
                                    transcript.append("local: explicit initialization recorded; new turns allowed. "
                                            + "No previous turn was resent; use explicit Reconnect.\n");
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
                        append(rawJsonLine);
                        return;
                    }
                    if (selected == null || !evidence.matches(selected.state))
                        throw new IllegalArgumentException("receipt does not match durable session/task/turn/request digest");
                    if ("turn.inspect.result".equals(evidence.kind)) {
                        pendingInspectRequestId = null;
                        if (evidence.completeReadback) {
                            evidenceFailure = null;
                            readbackRequired = false;
                            append("local: original turn records read back in full; effect outcomes remain the records' own evidence. "
                                    + "Only a new explicit Send can select another turn.");
                        } else {
                            readbackRequired = true;
                            append("local: inspection incomplete, absent, unknown or paginated; Send remains held. "
                                    + "No saved cursor or producer epoch was invented.");
                        }
                    } else {
                        append("local: acceptance matches durable request identity; Send remains held until explicit terminal readback");
                    }
                }
            }
        } catch (RuntimeException error) {
            synchronized (identityPublicationLock) {
                evidenceFailure = error.toString();
                readbackRequired = true;
            }
            append("local: invalid or conflicting readback; Send held, no automatic resend: " + error);
        }
        append(rawJsonLine);
    }

    @Override
    public void onDisconnected(String reason) {
        synchronized (identityPublicationLock) {
            pendingInspectRequestId = null;
            if (turnId != null) readbackRequired = true;
        }
        append("local disconnected: " + reason);
    }

    private void append(String value) {
        runOnUiThread(() -> transcript.append(value + "\n"));
    }

    private static String id(String prefix) {
        return prefix + "-" + UUID.randomUUID();
    }

    @Override
    protected void onDestroy() {
        synchronized (identityPublicationLock) {
            activityStopped = true;
            identityReady = false;
            pendingInspectRequestId = null;
        }
        client.shutdown();
        operations.shutdownNow();
        super.onDestroy();
    }

    @FunctionalInterface
    private interface CheckedOperation {
        void run() throws Exception;
    }
}
