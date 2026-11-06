package org.trillionnium.owneropen;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.IOException;
import java.util.UUID;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONObject;
import org.json.JSONArray;
import java.util.concurrent.ExecutorService;

/** Minimal truthful UI over the owner-open R5 broker wire. */
public final class OwnerOpenShellActivity extends Activity implements OwnerOpenClient.Listener {
    private static final int MAX_TRANSCRIPT_CHARACTERS = 64 * 1024;
    private final ExecutorService operations = new ThreadPoolExecutor(1, 1, 0,
            TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(16));
    private final AtomicBoolean destroyed = new AtomicBoolean();
    private final AtomicReference<String> turnInFlight = new AtomicReference<>();
    private final AtomicLong latestGeneration = new AtomicLong();
    private final Object displayLock = new Object();
    private final StringBuilder pendingDisplay = new StringBuilder();
    private boolean displayPosted;
    private volatile long rejectedGeneration = -1;
    private Map<String, Object> helloPayload;
    private Map<String, Object> acceptedScope;
    private String acceptedDigest;
    private Map<String, Object> lastGap;
    private OwnerOpenFrame.RecoveryPlan recovery;
    private long recoveryControlSequence;
    private boolean recoveryRunning;
    private boolean turnEnded;
    private final String sessionId = id("session");
    private final String taskId = id("task");
    private OwnerOpenClient client;
    private volatile String turnId;
    private String pendingStartRequest;
    private EditText prompt;
    private TextView transcript;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        client = new OwnerOpenClient(this);
        setContentView(buildView());
        runOperation("connect", () -> client.connect());
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
        root.addView(button(R.string.recover_output, view -> recoverOutput()),
                new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        transcript = new TextView(this);
        transcript.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
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
        String value = prompt.getText().toString();
        if (value.isBlank()) {
            append("Enter a prompt before sending.");
            return;
        }
        String selectedTurn = id("turn");
        if (!turnInFlight.compareAndSet(null, selectedTurn)) {
            append("A task is pending or running. Cancel or inspect it before sending another prompt.");
            return;
        }
        turnId = selectedTurn;
        runOperation("turn.start", () -> {
            ensureConnected();
            pendingStartRequest = client.startTurn(sessionId, taskId, selectedTurn, value);
            append("Task submitted.");
        });
    }

    private void cancelTurn() {
        String selectedTurn = turnId;
        if (selectedTurn == null) {
            append("No task has been started.");
            return;
        }
        runOperation("turn.cancel", () -> {
            ensureConnected();
            client.cancelTurn(sessionId, selectedTurn);
            append("Cancellation requested.");
        });
    }

    private void inspectTurn() {
        String selectedTurn = turnId;
        if (selectedTurn == null) {
            append("No task has been started.");
            return;
        }
        runOperation("turn.inspect", () -> {
            ensureConnected();
            if (acceptedScope == null || acceptedDigest == null) {
                append("No accepted task is available to inspect.");
                return;
            }
            client.inspectTurn(acceptedScope, acceptedDigest, 0);
        });
    }

    private void reconnect() {
        runOperation("reconnect", () -> {
            client.connect();
            recovery = null;
            recoveryRunning = false;
            append("Reconnected. Saved output can be inspected without restarting the task.");
        });
    }

    private void ensureConnected() throws IOException {
        if (!client.isConnected()) {
            client.connect();
        }
    }

    private void recoverOutput() {
        runOperation("Output recovery", () -> {
            ensureConnected();
            // connect() queues the new hello callback first, so negotiation is
            // processed before this read-only recovery action starts.
            enqueue(() -> {
                try {
                    if (lastGap == null || helloPayload == null || recoveryRunning) {
                        append("No new output gap is ready to recover.");
                        return;
                    }
                    recovery = new OwnerOpenFrame.RecoveryPlan(lastGap, helloPayload, acceptedDigest);
                    Object sequence = object(lastGap.get("payload")).get("next_control_seq");
                    if (!turnEnded && (!(sequence instanceof Number) || ((Number) sequence).longValue() < 0)) {
                        throw new IllegalArgumentException("Stream recovery is unavailable; inspect saved output instead.");
                    }
                    recoveryControlSequence = turnEnded ? 0 : ((Number) sequence).longValue();
                    recoveryRunning = true;
                    client.inspectRecovery(recovery);
                    append("Reading saved output…");
                } catch (Exception error) {
                    recoveryRunning = false;
                    recovery = null;
                    append("Output remains incomplete. Saved output needs explicit inspection.");
                }
            });
        });
    }

    private void runOperation(String label, CheckedOperation operation) {
        enqueue(() -> {
            try {
                operation.run();
            } catch (Exception error) {
                append(label + " failed. Reconnect or inspect saved output before continuing.");
            }
        });
    }

    private void enqueue(Runnable operation) {
        if (destroyed.get()) return;
        try {
            operations.execute(operation);
        } catch (RejectedExecutionException full) {
            rejectedGeneration = latestGeneration.get();
            client.close();
            append("Output processing is full. Delivery is incomplete; reconnect and inspect saved output.");
        }
    }

    @Override
    public void onFrame(String rawJsonLine) {
        onFrame(latestGeneration.get(), rawJsonLine);
    }

    @Override
    public void onFrame(long generation, String rawJsonLine) {
        if (destroyed.get()) return;
        latestGeneration.accumulateAndGet(generation, Math::max);
        enqueue(() -> {
            if (generation != latestGeneration.get() || generation == rejectedGeneration || destroyed.get()) return;
            try {
                JSONObject envelope = new JSONObject(rawJsonLine);
                if ("broker.hello.ack".equals(envelope.optString("kind"))) {
                    helloPayload = object(decode(envelope.getJSONObject("host_hello_ack").getJSONObject("payload")));
                    recovery = null;
                    recoveryRunning = false;
                    append("Connected.");
                    return;
                }
                if ("result".equals(envelope.optString("kind"))) {
                    // Only a correlated Host refusal resolves this pending start.
                    // Timeout, disconnect and broker errors can leave its outcome
                    // unknown, so they must not authorize another UI submission.
                    if (pendingStartRequest != null
                            && pendingStartRequest.equals(envelope.get("request_id"))
                            && "host.error".equals(envelope.getJSONObject("frame").optString("kind"))) {
                        pendingStartRequest = null;
                        finishTurn(turnId);
                        append("The task was rejected before acceptance. You can send a new prompt.");
                    }
                    return;
                }
                JSONObject host = "observation".equals(envelope.optString("kind"))
                        ? envelope.getJSONObject("frame") : envelope;
                handleHostFrame(object(decode(host)), generation);
            } catch (Exception error) {
                recoveryRunning = false;
                recovery = null;
                append("The output response could not be verified. Inspect saved output before resuming.");
            }
        });
    }

    private void handleHostFrame(Map<String, Object> frame, long generation) throws Exception {
        String kind = (String) frame.get("kind");
        if (kind == null || "result".equals(kind)) return;
        if ("turn.accepted".equals(kind) && sessionId.equals(frame.get("session_id"))
                && taskId.equals(frame.get("task_id")) && turnId.equals(frame.get("turn_id"))) {
            if (lastGap != null) append("The previous task still has an unresolved output gap.");
            acceptedScope = turnScope(frame);
            acceptedDigest = (String) object(frame.get("payload")).get("turn_request_sha256");
            pendingStartRequest = null;
            lastGap = null;
            recovery = null;
            recoveryRunning = false;
            turnEnded = false;
            append("Task started.");
            return;
        }
        if (isTurnTerminal(kind) && sessionId.equals(frame.get("session_id"))
                && taskId.equals(frame.get("task_id")) && turnId.equals(frame.get("turn_id"))
                && (acceptedScope == null || !sameTurn(frame, acceptedScope))) {
            // The Host can resolve startup before emitting turn.accepted.
            // Keep unrelated or earlier turn outcomes from releasing this slot.
            pendingStartRequest = null;
            turnEnded = true;
            finishTurn((String) frame.get("turn_id"));
            append("The task ended before acceptance. You can send a new prompt.");
            return;
        }
        if (acceptedScope == null || (!sameTurn(frame, acceptedScope)
                && !(kind.endsWith(".inspect.result") && recoveryRunning))) return;
        Map<String, Object> payload = object(frame.get("payload"));
        if ("stream.resync_required".equals(kind)) {
            lastGap = frame;
            // A growing gap supersedes an earlier plan. A pending inspector
            // response cannot acknowledge an outdated set of ranges.
            recovery = null;
            recoveryRunning = false;
            append("Some output is missing from this connection. Select Recover output to read saved observations.");
        } else if (kind.endsWith(".inspect.result") && recoveryRunning && recovery != null) {
            OwnerOpenFrame.RecoveryPlan plan = recovery;
            String domain = plan.pendingCursorDomain();
            if (!plan.observeInspection(frame)) return;
            renderInspection(payload, domain);
            // The UI accepts the bounded page before acknowledging it. A
            // reconnect or replacement gap invalidates this continuation.
            runOnUiThread(() -> enqueue(() -> {
                if (destroyed.get() || generation != latestGeneration.get() || recovery != plan || !recoveryRunning) return;
                try {
                    if (!plan.isComplete()) {
                        client.inspectRecovery(plan);
                    } else if (turnEnded) {
                        recoveryRunning = false;
                        lastGap = null;
                        recovery = null;
                        append("Saved output recovered. The task has already ended.");
                    } else {
                        client.resumeRecovery(plan, recoveryControlSequence);
                    }
                } catch (Exception error) {
                    recoveryRunning = false;
                    recovery = null;
                    append("Output remains incomplete. Inspect saved output before resuming.");
                }
            }));
        } else if ("stream.resume.ack".equals(kind)) {
            if (recoveryRunning && Boolean.FALSE.equals(payload.get("resync_required"))) {
                recoveryRunning = false;
                recovery = null;
                lastGap = null;
                append("Saved output recovered. Live delivery resumed.");
            }
        } else if (isTurnTerminal(kind)) {
            turnEnded = true;
            finishTurn((String) frame.get("turn_id"));
            if (payload.get("stream_gap") instanceof Map) {
                Map<String, Object> gap = new LinkedHashMap<>(frame);
                gap.put("payload",payload.get("stream_gap"));
                lastGap = gap;
                append("Task ended with missing output. Saved observations can be inspected.");
            } else {
                append("Task ended.");
            }
        } else if ("turn.inspect.result".equals(kind) || "job.inspect.result".equals(kind)) {
            renderInspection(payload);
        } else if ("host.error".equals(kind) || "job.error".equals(kind)) {
            recoveryRunning = false;
            recovery = null;
            append("The request was not confirmed. Inspect saved output before retrying recovery.");
        } else {
            renderObservation(frame);
        }
    }

    private static boolean isTurnTerminal(String kind) {
        return "turn.end".equals(kind) || "turn.failed".equals(kind)
                || "turn.rejected".equals(kind) || "turn.cancelled".equals(kind);
    }

    private void finishTurn(String selectedTurn) {
        String current = turnInFlight.get();
        if (current != null && current.equals(selectedTurn)) {
            turnInFlight.compareAndSet(current, null);
        }
    }

    private void renderInspection(Map<String, Object> payload) { renderInspection(payload,null); }

    private void renderInspection(Map<String, Object> payload, String domain) {
        Object stored = payload.get("frames");
        if (stored instanceof List && (domain == null || "transport_event".equals(domain))) {
            for (Object frame : (List<?>) stored) renderObservation(object(frame));
        }
        Object inspection = payload.get("inspection");
        if (inspection instanceof Map && (domain == null || "job_runtime_event".equals(domain))) {
            Object events = object(inspection).get("runtime_events");
            if (events instanceof List) {
                for (Object event : (List<?>) events) renderRuntimeEvent(object(event));
            }
        }
        if ("job_journal_record".equals(domain)) {
            Object records = payload.get("durable_records");
            if (records instanceof List) {
                for (Object record : (List<?>) records) {
                    Object envelope = object(record).get("payload");
                    if (envelope instanceof Map) {
                        Object event = object(envelope).get("payload");
                        if (event instanceof Map) renderRuntimeEvent(object(event));
                    }
                }
            }
        }
    }

    private void renderRuntimeEvent(Map<String, Object> value) {
        Object body = value.get("event");
        if (!(body instanceof Map)) return;
        Object bytes = object(body).get("bytes");
        if (!(bytes instanceof List)) return;
        List<?> numbers = (List<?>) bytes;
        byte[] raw = new byte[numbers.size()];
        for (int index = 0; index < raw.length; index++) raw[index] = ((Number) numbers.get(index)).byteValue();
        append(new String(raw, StandardCharsets.UTF_8));
    }

    private void renderObservation(Map<String, Object> frame) {
        String kind = (String) frame.get("kind");
        Map<String, Object> payload = object(frame.get("payload"));
        Object text = payload.get("text");
        if (text instanceof String && ("model.delta".equals(kind) || "model.message".equals(kind))) {
            append((String) text);
        } else if ("job.output".equals(kind) || "tool.stdout".equals(kind) || "tool.stderr".equals(kind) || "tool.pty".equals(kind)) {
            Object data = payload.get("data");
            if (data instanceof String && "base64".equals(payload.get("encoding"))) {
                append(new String(Base64.getDecoder().decode((String) data), StandardCharsets.UTF_8));
            } else if (data instanceof String) {
                append((String) data);
            }
        } else if ("job.result".equals(kind) || "tool.result".equals(kind)) {
            append("Operation completed.");
        }
    }

    private static Map<String, Object> turnScope(Map<String, Object> frame) {
        Map<String, Object> scope = new LinkedHashMap<>();
        for (String field : new String[]{"session_id","profile_id","task_id","turn_id","turn_stream_id"}) {
            if (!(frame.get(field) instanceof String)) throw new IllegalArgumentException("missing accepted scope");
            scope.put(field,frame.get(field));
        }
        return scope;
    }

    private static boolean sameTurn(Map<String, Object> frame, Map<String, Object> scope) {
        for (Map.Entry<String, Object> field : scope.entrySet()) {
            if (!field.getValue().equals(frame.get(field.getKey()))) return false;
        }
        return true;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        if (!(value instanceof Map)) throw new IllegalArgumentException("expected Host object");
        return (Map<String, Object>) value;
    }

    private static Object decode(Object value) throws Exception {
        if (value == JSONObject.NULL) return null;
        if (value instanceof JSONObject) {
            Map<String, Object> result = new LinkedHashMap<>();
            Iterator<String> keys = ((JSONObject) value).keys();
            while (keys.hasNext()) {
                String key = keys.next(); result.put(key,decode(((JSONObject) value).get(key)));
            }
            return result;
        }
        if (value instanceof JSONArray) {
            List<Object> result = new ArrayList<>();
            for (int index=0; index<((JSONArray) value).length(); index++) result.add(decode(((JSONArray) value).get(index)));
            return result;
        }
        return value;
    }

    @Override
    public void onDisconnected(String reason) {
        onDisconnected(latestGeneration.get(), reason);
    }

    @Override
    public void onDisconnected(long generation, String reason) {
        if (generation == latestGeneration.get() && !destroyed.get()) {
            enqueue(() -> {
                if (generation != latestGeneration.get() || destroyed.get()) return;
                recoveryRunning = false;
                recovery = null;
                append("Disconnected. Task outcome is unchanged; reconnect and inspect saved output.");
            });
        }
    }

    private void append(String value) {
        if (destroyed.get()) return;
        synchronized (displayLock) {
            pendingDisplay.append(tail(value,MAX_TRANSCRIPT_CHARACTERS)).append('\n');
            if (pendingDisplay.length() > MAX_TRANSCRIPT_CHARACTERS) {
                String bounded = tail(pendingDisplay.toString(),MAX_TRANSCRIPT_CHARACTERS);
                pendingDisplay.setLength(0); pendingDisplay.append(bounded);
            }
            if (displayPosted) return;
            displayPosted = true;
        }
        runOnUiThread(() -> {
            if (destroyed.get()) return;
            String pending;
            synchronized (displayLock) {
                pending = pendingDisplay.toString(); pendingDisplay.setLength(0); displayPosted = false;
            }
            String combined = transcript.getText().toString() + pending;
            if (combined.length() > MAX_TRANSCRIPT_CHARACTERS) {
                String notice = "Older output has been omitted from this view.\n";
                combined = notice + tail(combined,MAX_TRANSCRIPT_CHARACTERS-notice.length());
            }
            transcript.setText(combined);
        });
    }

    private static String tail(String value, int maximum) {
        int start = Math.max(0,value.length()-maximum);
        if (start > 0 && start < value.length() && Character.isLowSurrogate(value.charAt(start))) start++;
        return value.substring(start);
    }

    private static String id(String prefix) {
        return prefix + "-" + UUID.randomUUID();
    }

    @Override
    protected void onDestroy() {
        destroyed.set(true);
        client.shutdown();
        operations.shutdownNow();
        super.onDestroy();
    }

    @FunctionalInterface
    private interface CheckedOperation {
        void run() throws Exception;
    }
}
